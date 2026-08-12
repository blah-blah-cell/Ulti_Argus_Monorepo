"""Local dashboard authentication helpers."""
import hmac
import os
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from web.api.deps import API_KEY, get_api_key, limiter


class VerifyRequest(BaseModel):
    token: str


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/check")
@limiter.limit("60/minute")
async def check_auth(request: Request, _: str = Depends(get_api_key)):
    return {"status": "authenticated"}


@router.post("/logout")
@limiter.limit("10/minute")
async def logout(request: Request, response: Response):
    response.delete_cookie("argus_session", path="/")
    return {"status": "logged_out"}


@router.post("/verify")
@limiter.limit("10/minute")
async def verify_auth(
    request: Request,
    response: Response,
    body: Annotated[VerifyRequest, Body()],
):
    local_token = os.environ.get("ARGUS_LOCAL_TOKEN", "")
    token = body.token
    valid = bool(token) and (
        (bool(local_token) and hmac.compare_digest(token, local_token))
        or hmac.compare_digest(token, API_KEY)
    )
    if not valid:
        raise HTTPException(status_code=401, detail="Invalid token")
    response.set_cookie(
        key="argus_session",
        value=token,
        httponly=True,
        secure=False,
        samesite="strict",
        max_age=8 * 60 * 60,
        path="/",
    )
    return {"status": "authenticated"}
