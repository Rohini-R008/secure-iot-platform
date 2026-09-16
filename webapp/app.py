"""FastAPI RBAC web app: login, roles (operator/admin), device list.

Every login attempt and access attempt is written to the audit bucket.
Role checks are enforced server-side. Device revocation UI is present for
admins and gets wired to the real mechanism in Phase 3c.
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

# Make the shared audit helper importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from common.audit import audit  # noqa: E402
from webapp.users import verify_user, get_role, ROLE_ADMIN  # noqa: E402

SECRET_KEY = os.getenv("WEBAPP_SECRET_KEY")
if not SECRET_KEY or "change-me" in SECRET_KEY:
    raise RuntimeError("WEBAPP_SECRET_KEY not set. Configure .env.")

# Certs live here; in 3c we'll list device certs from this directory.
CERT_DIR = ROOT / "certs" / "out"

# Prefer Git Bash explicitly. shutil.which("bash") can resolve to the WSL
# relay on Windows, which fails if WSL isn't installed — so check known
# Git Bash locations first and only fall back to PATH as a last resort.
_BASH_CANDIDATES = [
    r"C:\Program Files\Git\usr\bin\bash.exe",
    r"C:\Program Files\Git\bin\bash.exe",
    r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
]
BASH_PATH = next((p for p in _BASH_CANDIDATES if Path(p).exists()),
                 shutil.which("bash") or _BASH_CANDIDATES[0])
REVOKE_SCRIPT = ROOT / "certs" / "revoke_device.sh"

app = FastAPI(title="Secure IoT — Admin")
# Tracks revoked device ids for UI display (source of truth is the CRL itself).
_REVOKED: set[str] = set()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=False)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


# ----------------------------- auth helpers -----------------------------
def current_user(request: Request) -> dict | None:
    username = request.session.get("username")
    role = request.session.get("role")
    if username and role:
        return {"username": username, "role": role}
    return None


def require_login(request: Request) -> dict:
    user = current_user(request)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not logged in",
            headers={"Location": "/login"},
        )
    return user


def require_admin(request: Request) -> dict:
    user = require_login(request)
    if user["role"] != ROLE_ADMIN:
        # Audit the forbidden attempt — this is a security-relevant event.
        audit("forbidden_access", actor=user["username"],
              target=str(request.url.path), outcome="failure",
              detail="non-admin attempted admin action")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="admin role required")
    return user


def list_device_ids() -> list[str]:
    """Device ids = the CN of each *.crt in certs/out, excluding infra certs."""
    exclude = {"ca", "server", "processor"}
    ids = []
    for crt in sorted(CERT_DIR.glob("*.crt")):
        name = crt.stem
        if name not in exclude:
            ids.append(name)
    return ids


# ------------------------------- routes ---------------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if current_user(request):
        return RedirectResponse("/devices", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
        return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    role = verify_user(username, password)
    if role is None:
        audit("login", actor=username, outcome="failure",
              detail="invalid credentials")
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid username or password"},
            status_code=401,
        )
    request.session["username"] = username
    request.session["role"] = role
    audit("login", actor=username, outcome="success", detail=f"role={role}")
    return RedirectResponse("/devices", status_code=302)


@app.get("/logout")
def logout(request: Request):
    user = current_user(request)
    if user:
        audit("logout", actor=user["username"], outcome="success")
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.get("/devices", response_class=HTMLResponse)
def devices(request: Request):
    user = require_login(request)
    audit("view_devices", actor=user["username"], outcome="success")
    device_rows = [
        {"id": d, "revoked": d in _REVOKED} for d in list_device_ids()
    ]
    return templates.TemplateResponse(
        request,
        "devices.html",
        {
            "user": user,
            "devices": device_rows,
            "is_admin": user["role"] == ROLE_ADMIN,
        },
    )

def _is_in_crl(device_id: str) -> bool:
    """Return True only if this device's cert serial appears in the CRL.
    This is the source of truth — we never trust a script exit code alone."""
    cert = CERT_DIR / f"{device_id}.crt"
    crl = CERT_DIR / "crl.pem"
    if not cert.exists() or not crl.exists():
        return False
    openssl = shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe"
    try:
        serial = subprocess.run(
            [openssl, "x509", "-in", str(cert), "-noout", "-serial"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip().split("=")[-1].upper()
        crl_text = subprocess.run(
            [openssl, "crl", "-in", str(crl), "-noout", "-text"],
            capture_output=True, text=True, timeout=10,
        ).stdout.upper()
        return serial in crl_text
    except Exception:
        return False

@app.post("/revoke/{device_id}")
def revoke_device(device_id: str, request: Request):
    user = require_admin(request)  # admin-only; audits forbidden attempts

    if not device_id.replace("-", "").replace("_", "").isalnum():
        audit("revoke_device", actor=user["username"], target=device_id,
              outcome="failure", detail="invalid device id")
        raise HTTPException(status_code=400, detail="invalid device id")

    cert = CERT_DIR / f"{device_id}.crt"
    if not cert.exists():
        audit("revoke_device", actor=user["username"], target=device_id,
              outcome="failure", detail="unknown device")
        raise HTTPException(status_code=404, detail="unknown device")

    # 1. Run the revoke script.
    script_posix = "/" + str(REVOKE_SCRIPT).replace("\\", "/").replace(":", "", 1)
    result = subprocess.run(
        [BASH_PATH, "-lc", f'"{script_posix}" "{device_id}"'],
        cwd=str(ROOT), capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        combined = (result.stdout + "\n" + result.stderr).strip()
        audit("revoke_device", actor=user["username"], target=device_id,
              outcome="failure", detail=combined[:300])
        raise HTTPException(status_code=500, detail=f"revoke failed: {combined[:500]}")

    # 2. VERIFY the CRL actually contains this device's serial before trusting it.
    if not _is_in_crl(device_id):
        audit("revoke_device", actor=user["username"], target=device_id,
              outcome="failure", detail="script exited 0 but device not in CRL")
        raise HTTPException(status_code=500,
                            detail="revoke reported success but CRL does not list the device")

    # 3. Restart the broker so it reloads the CRL and drops connections.
    docker_exe = shutil.which("docker") or "docker"
    restart = subprocess.run(
        [docker_exe, "compose", "restart", "broker"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=90,
    )
    if restart.returncode != 0:
        detail = (restart.stdout + "\n" + restart.stderr).strip()[:400]
        audit("revoke_device", actor=user["username"], target=device_id,
              outcome="failure", detail=f"CRL updated but broker restart failed: {detail}")
        raise HTTPException(status_code=500,
                            detail=f"Certificate revoked but broker restart failed: {detail}")

    # 4. Only now is it truly revoked and enforced.
    _REVOKED.add(device_id)
    audit("revoke_device", actor=user["username"], target=device_id,
          outcome="success", detail="certificate revoked; CRL verified; broker reloaded")
    return RedirectResponse("/devices", status_code=302)

# Redirect unauthenticated users to the login page instead of a raw 401.
@app.exception_handler(HTTPException)
def auth_redirect(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return RedirectResponse("/login", status_code=302)
    return HTMLResponse(f"<h1>{exc.status_code}</h1><p>{exc.detail}</p>",
                        status_code=exc.status_code)