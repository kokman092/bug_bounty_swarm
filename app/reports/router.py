"""
app/reports/router.py
─────────────────────
FastAPI router for retrieving final investigation reports.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.exceptions import InvestigationNotFoundError
from app.core.security import AuthUser, require_user
from app.investigations.service import InvestigationService
from app.reports.schemas import InvestigationReport
from app.reports.service import ReportService

router = APIRouter(prefix="/investigations", tags=["reports"])


def get_report_service() -> ReportService:
    return ReportService()


def get_investigation_service() -> InvestigationService:
    return InvestigationService()


@router.get(
    "/{investigation_id}/report",
    response_model=InvestigationReport,
    summary="Get final security report for completed investigation",
)
async def get_investigation_report(
    investigation_id: str,
    user: AuthUser = Depends(require_user),
    inv_service: InvestigationService = Depends(get_investigation_service),
    report_service: ReportService = Depends(get_report_service),
) -> InvestigationReport:
    """
    Retrieve structured and Markdown security assessment report.
    Validates ownership of the investigation.
    """
    # 1. Ownership check
    try:
        await inv_service.get_investigation(investigation_id, user)
    except InvestigationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found",
        )

    # 2. Retrieve report
    try:
        return await report_service.get_report(investigation_id)
    except InvestigationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for investigation '{investigation_id}' is not yet available or failed to generate",
        )
