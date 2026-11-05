# -*- coding: utf-8 -*-
"""
Direct Google sign-in for self-hosted deployments (no Firebase, no openagents.org).

GET /v1/auth/google/start?returnTo=/path   -> 302 to Google consent
GET /v1/auth/google/callback?code&state    -> verifies Google, mints a workspace
                                              session JWT, 302 to /auth/google#...

Enabled only when GOOGLE_LOGIN_CLIENT_ID, GOOGLE_LOGIN_CLIENT_SECRET,
GOOGLE_LOGIN_REDIRECT_URI and WORKSPACE_SESSION_SECRET are all set. The session
JWT is the same one /v1/auth/session issues, so the rest of the API needs no
change. GOOGLE_LOGIN_ALLOWED_DOMAIN (e.g. cloudnsite.com) restricts sign-in to
one Google Workspace domain. Workspace access still requires membership.
"""

import logging
import os
import secrets
import time
from urllib.parse import urlencode, quote

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, PlainTextResponse

from app.config import config
from app.firebase_auth import mint_workspace_session, workspace_session_enabled

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/v1/auth/google", tags=["Auth"])

CLIENT_ID = os.environ.get("GOOGLE_LOGIN_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("GOOGLE_LOGIN_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("GOOGLE_LOGIN_REDIRECT_URI", "")
ALLOWED_DOMAIN = os.environ.get("GOOGLE_LOGIN_ALLOWED_DOMAIN", "").strip().lower()

_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URL = "https://oauth2.googleapis.com/token"
_NONCE_COOKIE = "oa_google_nonce"
_STATE_ISS = "openagents-google-login"


def enabled() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET and REDIRECT_URI and workspace_session_enabled())


def _safe_return(path: str) -> str:
    # isprintable: browsers strip tabs and newlines, so "/\t/evil.com" means "//evil.com".
    if path and path.startswith("/") and not path.startswith("//") and "\\" not in path and path.isprintable():
        return path
    return "/"


@router.get("/start")
def start(returnTo: str = "/"):
    if not enabled():
        return PlainTextResponse("Google sign-in is not configured", status_code=503)
    import jwt

    nonce = secrets.token_urlsafe(24)
    state = jwt.encode(
        {"iss": _STATE_ISS, "n": nonce, "r": _safe_return(returnTo), "exp": int(time.time()) + 600},
        config.WORKSPACE_SESSION_SECRET, algorithm="HS256",
    )
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "prompt": "select_account",
    }
    if ALLOWED_DOMAIN:
        params["hd"] = ALLOWED_DOMAIN
    resp = RedirectResponse(f"{_AUTH_URL}?{urlencode(params)}", status_code=302)
    resp.set_cookie(_NONCE_COOKIE, nonce, max_age=600, httponly=True, secure=True,
                    samesite="lax", path="/v1/auth/google")
    return resp


def _fail(msg: str):
    logger.warning("google_login: %s", msg)
    return RedirectResponse(f"/login?error={quote(msg)}", status_code=302)


@router.get("/callback")
def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if not enabled():
        return PlainTextResponse("Google sign-in is not configured", status_code=503)
    if error or not code or not state:
        return _fail(error or "Sign-in was cancelled")
    import jwt
    import httpx
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests

    try:
        st = jwt.decode(state, config.WORKSPACE_SESSION_SECRET, algorithms=["HS256"], issuer=_STATE_ISS)
    except Exception:
        return _fail("Sign-in expired, please try again")
    cookie_nonce = request.cookies.get(_NONCE_COOKIE, "")
    if not cookie_nonce or not secrets.compare_digest(cookie_nonce, st.get("n", "")):
        return _fail("Sign-in could not be verified, please try again")

    try:
        tok = httpx.post(_TOKEN_URL, data={
            "code": code, "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI, "grant_type": "authorization_code",
        }, timeout=10.0)
        tok.raise_for_status()
        raw_id = tok.json()["id_token"]
        claims = google_id_token.verify_oauth2_token(raw_id, google_requests.Request(), CLIENT_ID)
    except Exception as e:  # noqa: BLE001
        return _fail(f"Google sign-in failed ({type(e).__name__})")

    email = (claims.get("email") or "").strip().lower()
    if not email or claims.get("email_verified") is not True:
        return _fail("Google account email is not verified")
    if claims.get("nonce") != st.get("n"):
        return _fail("Sign-in could not be verified, please try again")
    if ALLOWED_DOMAIN and (claims.get("hd", "").lower() != ALLOWED_DOMAIN or not email.endswith("@" + ALLOWED_DOMAIN)):
        return _fail(f"Only {ALLOWED_DOMAIN} accounts can sign in")

    session, exp = mint_workspace_session({
        "email": email, "display_name": claims.get("name"), "email_verified": True,
    })
    logger.info("google_login: issued workspace session for %s", email)
    frag = urlencode({"s": session, "e": email, "n": claims.get("name") or "", "x": exp, "r": st.get("r", "/")})
    resp = RedirectResponse(f"/auth/google#{frag}", status_code=302)
    resp.delete_cookie(_NONCE_COOKIE, path="/v1/auth/google")
    return resp
