"""Cliente HTTP somente leitura para o SAC Data Export Service.

Endpoints (documentação SAP / SAP Community):
  GET /api/v1/dataexport/administration/Namespaces
  GET /api/v1/dataexport/administration/Namespaces(NamespaceID='<ns>')/Providers
  GET /api/v1/dataexport/providers/<ns>/<provider>              (service document)
  GET /api/v1/dataexport/providers/<ns>/<provider>/$metadata
  GET /api/v1/dataexport/providers/<ns>/<provider>/<EntitySet>  (FactData e master data)

Entity sets de master data NÃO são fixados no código: são lidos do service
document de cada modelo. Salvaguardas de somente leitura:
  - único verbo HTTP: GET;
  - paths restritos ao prefixo do Data Export Service;
  - header `Prefer` (odata.track-changes cria assinatura de delta no SAC) bloqueado;
  - parâmetros deltaid/externalid (assinaturas de delta) bloqueados.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Iterator
from urllib.parse import parse_qs, quote, urljoin, urlparse

import httpx
from defusedxml import ElementTree as ET

from sac_mcp.auth import TokenManager
from sac_mcp.config import Config
from sac_mcp.redaction import redact

log = logging.getLogger(__name__)

BASE_PATH = "/api/v1/dataexport"
_ALLOWED_PATH = re.compile(r"^/api/v1/dataexport/(administration|providers)(/|$)")
_ID = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
_ENTITY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_FORBIDDEN_PARAMS = {"deltaid", "externalid"}
_FORBIDDEN_HEADERS = {"prefer"}


class SacError(RuntimeError):
    pass


class SacPermissionError(SacError):
    pass


class SacNotFound(SacError):
    pass


class PolicyViolation(SacError):
    """Tentativa de operação fora da política somente leitura / allowlist."""


def validate_id(value: str, what: str) -> str:
    if not isinstance(value, str) or not _ID.match(value):
        raise PolicyViolation(f"{what} inválido: {value!r}")
    return value


def validate_entity(value: str) -> str:
    if not isinstance(value, str) or not _ENTITY.match(value):
        raise PolicyViolation(f"Entity set inválido: {value!r}")
    return value


class SacClient:
    def __init__(self, config: Config, tokens: TokenManager, http: httpx.Client) -> None:
        self.config = config
        self.tokens = tokens
        self.http = http
        self._host = urlparse(config.tenant_url).hostname

    # ------------------------------------------------------------ core GET
    def _check_url(self, url: str) -> None:
        p = urlparse(url)
        if p.scheme != "https" or p.hostname != self._host:
            raise PolicyViolation(f"URL fora do tenant configurado: {p.scheme}://{p.hostname}")
        if not _ALLOWED_PATH.match(p.path):
            raise PolicyViolation(f"Path não permitido: {p.path}")
        if _FORBIDDEN_PARAMS & {k.lower() for k in parse_qs(p.query)}:
            raise PolicyViolation("Parâmetros de assinatura de delta (deltaid/externalid) não são permitidos.")

    def get(self, url: str, params: dict[str, Any] | None = None, accept: str = "application/json",
            headers: dict[str, str] | None = None) -> httpx.Response:
        if headers and _FORBIDDEN_HEADERS & {h.lower() for h in headers}:
            raise PolicyViolation("Header 'Prefer' bloqueado: odata.track-changes cria assinatura no SAC.")
        if params and _FORBIDDEN_PARAMS & {k.lower() for k in params}:
            raise PolicyViolation("Parâmetros de assinatura de delta (deltaid/externalid) não são permitidos.")
        self._check_url(url)
        for attempt in (1, 2):
            hdrs = {"Authorization": f"Bearer {self.tokens.get_access_token()}", "Accept": accept}
            if self.config.send_custom_auth_header:
                hdrs["x-sap-sac-custom-auth"] = "true"
            if headers:
                hdrs.update(headers)
            resp = self.http.request("GET", url, params=params, headers=hdrs)
            if resp.status_code == 401 and attempt == 1:
                self.tokens.invalidate()  # token pode ter sido revogado; tenta 1x
                continue
            break
        if resp.status_code == 401:
            raise SacPermissionError("401 Não autenticado: token rejeitado pelo SAC.")
        if resp.status_code == 403:
            raise SacPermissionError("403 Sem permissão: o usuário/cliente não tem acesso a este recurso no SAC.")
        if resp.status_code == 404:
            raise SacNotFound(f"404 Não encontrado: {urlparse(url).path}")
        if resp.status_code >= 400:
            raise SacError(f"HTTP {resp.status_code}: {redact(resp.text[:500])}")
        return resp

    def url(self, path: str) -> str:
        return self.config.tenant_url + BASE_PATH + path

    # ------------------------------------------------------------ administration
    def list_namespaces(self) -> list[dict[str, Any]]:
        return _values(self.get(self.url("/administration/Namespaces")).json())

    def list_providers(self, namespace: str = "sac") -> list[dict[str, Any]]:
        ns = validate_id(namespace, "NamespaceID")
        path = f"/administration/Namespaces(NamespaceID='{quote(ns, safe='')}')/Providers"
        return _values(self.get(self.url(path)).json())

    # ------------------------------------------------------------ provider
    def _provider_base(self, namespace: str, provider: str) -> str:
        ns, pid = validate_id(namespace, "NamespaceID"), validate_id(provider, "ProviderID")
        if not self.config.is_model_allowed(pid):
            raise PolicyViolation(
                f"Modelo {pid!r} fora da allowlist. Inclua-o em model_allowlist no config.json "
                "(lista vazia = nenhum modelo liberado; '*' = todos)."
            )
        return self.url(f"/providers/{quote(ns, safe='')}/{quote(pid, safe='')}")

    def entity_sets(self, namespace: str, provider: str) -> list[str]:
        body = self.get(self._provider_base(namespace, provider)).json()
        return [e.get("name") or e.get("url") for e in _values(body) if (e.get("name") or e.get("url"))]

    def metadata(self, namespace: str, provider: str) -> dict[str, Any]:
        resp = self.get(self._provider_base(namespace, provider) + "/$metadata", accept="application/xml")
        return summarize_metadata(resp.text)

    def iter_rows(self, namespace: str, provider: str, entity_set: str, *, top: int,
                  select: list[str] | None = None, filter_: str | None = None,
                  orderby: str | None = None) -> Iterator[dict[str, Any]]:
        """Itera linhas seguindo @odata.nextLink, parando em `top` linhas."""
        es = validate_entity(entity_set)
        available = self.entity_sets(namespace, provider)
        if es not in available:
            raise SacNotFound(f"Entity set {es!r} não existe neste modelo. Disponíveis: {available}")
        params: dict[str, Any] = {"$top": str(top)}
        if select:
            for col in select:
                validate_entity(col)
            params["$select"] = ",".join(select)
        if filter_:
            params["$filter"] = filter_
        if orderby:
            params["$orderby"] = orderby
        url: str | None = self._provider_base(namespace, provider) + "/" + es
        count = 0
        while url and count < top:
            body = self.get(url, params=params).json()
            for row in _values(body):
                if count >= top:
                    return
                row.pop("__metadata", None)
                yield row
                count += 1
            nxt = body.get("@odata.nextLink") or (body.get("d") or {}).get("__next")
            url = urljoin(url, nxt) if nxt else None
            params = None  # nextLink já contém a query


def _values(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, dict):
        if isinstance(body.get("value"), list):  # OData v4
            return body["value"]
        d = body.get("d")
        if isinstance(d, dict) and isinstance(d.get("results"), list):  # OData v2
            return d["results"]
        if isinstance(d, list):
            return d
    if isinstance(body, list):
        return body
    return []


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def summarize_metadata(xml_text: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text)
    types: dict[str, Any] = {}
    sets: list[dict[str, str]] = []
    for el in root.iter():
        name = _local(el.tag)
        if name == "EntityType":
            keys = [_local_attr(k) for k in el.iter() if _local(k.tag) == "PropertyRef"]
            props = [
                {"name": p.get("Name"), "type": p.get("Type")}
                for p in el if _local(p.tag) == "Property"
            ]
            types[el.get("Name")] = {"keys": keys, "properties": props}
        elif name == "EntitySet":
            sets.append({"name": el.get("Name"), "entity_type": (el.get("EntityType") or "").rsplit(".", 1)[-1]})
    return {"entity_sets": sets, "entity_types": types}


def _local_attr(el: Any) -> str:
    return el.get("Name")
