"""FastAPI RBAC web app: login, roles (operator/admin), device list.

Every login attempt and access attempt is written to the audit bucket.
Role checks are enforced server-side. Device revocation UI is present for
admins and gets wired to the real mechanism in Phase 3c.
"""
import os
import sys
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

app = FastAPI(title="Secure IoT — Admin")
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
    return templates.TemplateResponse(
        request,
        "devices.html",
        {
            "user": user,
            "devices": list_device_ids(),
            "is_admin": user["role"] == ROLE_ADMIN,
        },
    )


# Redirect unauthenticated users to the login page instead of a raw 401.
@app.exception_handler(HTTPException)
def auth_redirect(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return RedirectResponse("/login", status_code=302)
    return HTMLResponse(f"<h1>{exc.status_code}</h1><p>{exc.detail}</p>",
                        status_code=exc.status_code)