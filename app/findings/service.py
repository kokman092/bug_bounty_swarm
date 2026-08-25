"""
app/findings/service.py
───────────────────────
FindingService — Managing finding creation, deduplication, and overflow to Cloud Storage.
"""
from __future__ import annotations

import json
from datetime import datetime

from app.core.logging import get_logger
from app.db.firestore import findings_ref
from app.db.storage import evidence_path, upload_json
from app.findings.schemas import Finding, FindingStatus, Hypothesis

logger = get_logger(__name__)

MAX_INLINE_EVIDENCE_BYTES = 16_384  # 16KB


class FindingService:
    """Service layer managing findings in Firestore and Cloud Storage."""

    async def save_finding(
        self,
        investigation_id: str,
        finding: Finding,
    ) -> Finding:
        """
        Persist finding. If raw_evidence_inline exceeds 16KB, offload to Cloud Storage
        and store GCS reference.
        """
        doc_data = finding.model_dump(mode="json")

        if finding.raw_evidence_inline:
            serialized = json.dumps(finding.raw_evidence_inline)
            if len(serialized.encode("utf-8")) > MAX_INLINE_EVIDENCE_BYTES:
                gcs_rel_path = evidence_path(investigation_id, finding.finding_id)
                try:
                    gcs_uri = await upload_json(gcs_rel_path, finding.raw_evidence_inline)
                    doc_data["evidence_ref"] = gcs_uri
                    doc_data["raw_evidence_inline"] = None
                    finding.evidence_ref = gcs_uri
                    finding.raw_evidence_inline = None
                    logger.info("evidence_offloaded_to_gcs", gcs_uri=gcs_uri)
                except Exception as exc:
                    logger.warning("evidence_gcs_upload_failed", error=str(exc))

        ref = findings_ref(investigation_id).document(finding.finding_id)
        await ref.set(doc_data)
        logger.info(
            "finding_saved",
            investigation_id=investigation_id,
            finding_id=finding.finding_id,
            status=finding.status.value,
        )
        return finding

    async def list_findings(
        self,
        investigation_id: str,
        status_filter: FindingStatus | None = None,
    ) -> list[Finding]:
        """Fetch all findings for an investigation."""
        ref = findings_ref(investigation_id)
        if status_filter:
            query = ref.where("status", "==", status_filter.value)
        else:
            query = ref.order_by("created_at")

        docs = await query.get()
        findings: list[Finding] = []
        for doc in docs:
            data = doc.to_dict()
            if data:
                findings.append(Finding(**data))
        return findings

    async def is_duplicate_hypothesis(
        self,
        investigation_id: str,
        hypothesis: Hypothesis,
    ) -> bool:
        """
        Check if an identical endpoint + vuln_class has already been tested.
        """
        existing = await self.list_findings(investigation_id)
        for f in existing:
            if f.endpoint == hypothesis.endpoint and f.vuln_class == hypothesis.vuln_class:
                return True
        return False
