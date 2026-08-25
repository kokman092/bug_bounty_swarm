"""
app/reports/service.py
──────────────────────
ReportService — Saving, retrieving, and offloading reports.
"""
from __future__ import annotations

from app.core.exceptions import InvestigationNotFoundError
from app.core.logging import get_logger
from app.db.firestore import reports_ref
from app.db.storage import report_path, upload_json
from app.reports.schemas import InvestigationReport

logger = get_logger(__name__)

MAX_INLINE_REPORT_BYTES = 500_000  # 500KB


class ReportService:
    """Service layer managing finalized security reports."""

    async def save_report(
        self,
        report: InvestigationReport,
    ) -> InvestigationReport:
        doc_data = report.model_dump(mode="json")

        # Offload massive markdown reports to Cloud Storage
        if len(report.markdown_report.encode("utf-8")) > MAX_INLINE_REPORT_BYTES:
            gcs_rel_path = report_path(report.investigation_id)
            try:
                gcs_uri = await upload_json(gcs_rel_path, report.markdown_report)
                doc_data["markdown_report_ref"] = gcs_uri
                doc_data["markdown_report"] = report.markdown_report[:10000] + "\n\n[Full report offloaded to GCS]"
                report.markdown_report_ref = gcs_uri
                logger.info("report_markdown_offloaded", gcs_uri=gcs_uri)
            except Exception as exc:
                logger.warning("report_gcs_upload_failed", error=str(exc))

        ref = reports_ref().document(report.investigation_id)
        await ref.set(doc_data)
        logger.info("report_persisted", investigation_id=report.investigation_id, findings=report.finding_count)
        return report

    async def get_report(
        self,
        investigation_id: str,
    ) -> InvestigationReport:
        ref = reports_ref().document(investigation_id)
        snapshot = await ref.get()
        if not snapshot.exists:
            raise InvestigationNotFoundError(investigation_id)
        data = snapshot.to_dict() or {}
        return InvestigationReport(**data)
