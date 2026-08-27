"""
app/investigations/router.py
────────────────────────────
FastAPI router for investigation lifecycle operations.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.exceptions import (
    InvestigationAlreadyTerminalError,
    InvestigationNotFoundError,
    InvalidStateTransitionError,
    PrivateIPAccessError,
    TargetNotAuthorizedError,
    URLNormalizationError,
)
from app.core.security import AuthUser, require_internal, require_user
from app.investigations.runner import InvestigationRunner
from app.investigations.schemas import (
    CancelInvestigationResponse,
    CreateInvestigationRequest,
    CreateInvestigationResponse,
    InvestigationResponse,
)
from app.investigations.service import InvestigationService

router = APIRouter(prefix="/investigations", tags=["investigations"])
internal_router = APIRouter(prefix="/internal/investigations", tags=["internal"])


def get_investigation_service() -> InvestigationService:
    return InvestigationService()


@router.post(
    "",
    response_model=CreateInvestigationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and start a new security investigation",
)
async def create_investigation(
    request: CreateInvestigationRequest,
    user: AuthUser = Depends(require_user),
    service: InvestigationService = Depends(get_investigation_service),
) -> CreateInvestigationResponse:
    try:
        return await service.create_investigation(request, user)
    except URLNormalizationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message)
    except (TargetNotAuthorizedError, PrivateIPAccessError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=exc.message)


@router.get(
    "/{investigation_id}",
    response_model=InvestigationResponse,
    summary="Get current investigation status and phase",
)
async def get_investigation(
    investigation_id: str,
    user: AuthUser = Depends(require_user),
    service: InvestigationService = Depends(get_investigation_service),
) -> InvestigationResponse:
    try:
        return await service.get_investigation(investigation_id, user)
    except InvestigationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )


@router.delete(
    "/{investigation_id}",
    response_model=CancelInvestigationResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Cancel an active investigation",
)
async def cancel_investigation(
    investigation_id: str,
    user: AuthUser = Depends(require_user),
    service: InvestigationService = Depends(get_investigation_service),
) -> CancelInvestigationResponse:
    try:
        new_status = await service.cancel_investigation(investigation_id, user)
        return CancelInvestigationResponse(
            investigation_id=investigation_id,
            status=new_status,
        )
    except InvestigationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )
    except (InvestigationAlreadyTerminalError, InvalidStateTransitionError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.message)


@router.post(
    "/{investigation_id}/ingest/burp-history",
    status_code=status.HTTP_200_OK,
    summary="Ingest Burp Suite XML or HAR recorded traffic into active investigation",
)
async def ingest_burp_history(
    investigation_id: str,
    payload: dict,
    user: AuthUser = Depends(require_user),
    service: InvestigationService = Depends(get_investigation_service),
) -> dict:
    burp_xml = payload.get("burp_xml")
    har_json = payload.get("har_json")

    from app.tools.burp.history_parser import parse_burp_xml_history, parse_har_history
    if burp_xml:
        parsed = parse_burp_xml_history(burp_xml)
    elif har_json:
        parsed = parse_har_history(har_json)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Must provide 'burp_xml' or 'har_json'")

    return {
        "status": "ingested",
        "investigation_id": investigation_id,
        "total_requests": parsed.get("total_requests", 0),
        "observed_cookies": parsed.get("observed_cookies", {}),
        "observed_auth_headers": parsed.get("observed_auth_headers", []),
    }


# ── Internal Route (Invoked by Cloud Tasks) ───────────────────────────────────

@internal_router.post(
    "/{investigation_id}/run",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_internal)],
    summary="Internal endpoint for Cloud Tasks runner dispatch",
)
async def run_investigation_internal(
    investigation_id: str,
) -> dict[str, str]:
    runner = InvestigationRunner()
    await runner.run_investigation(investigation_id)
    return {"status": "dispatched", "investigation_id": investigation_id}
