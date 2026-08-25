"""
app/db/firestore.py
────────────────────
Firestore client singleton with emulator support and robust in-memory development fallback.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime
from functools import lru_cache
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Global in-memory storage for offline development
_IN_MEMORY_STORE: dict[str, dict[str, dict[str, Any]]] = {
    "investigations": {},
    "authorized_targets": {},
    "reports": {},
}


class _InMemoryDocSnapshot:
    def __init__(self, doc_id: str, data: dict[str, Any] | None):
        self.id = doc_id
        self._data = data
        self.exists = data is not None

    def to_dict(self) -> dict[str, Any] | None:
        return self._data.copy() if self._data else None


class _InMemoryDocRef:
    def __init__(self, collection_name: str, doc_id: str, subcollections: dict[str, Any] | None = None):
        self.id = doc_id
        self.collection_name = collection_name
        self._subcollections = subcollections or {}

    async def set(self, data: dict[str, Any], merge: bool = False) -> None:
        store = _IN_MEMORY_STORE.setdefault(self.collection_name, {})
        if merge and self.id in store:
            store[self.id].update(data)
        else:
            store[self.id] = data.copy()

    async def update(self, data: dict[str, Any]) -> None:
        store = _IN_MEMORY_STORE.setdefault(self.collection_name, {})
        if self.id in store:
            store[self.id].update(data)
        else:
            store[self.id] = data.copy()

    async def get(self, transaction: Any = None) -> _InMemoryDocSnapshot:
        store = _IN_MEMORY_STORE.setdefault(self.collection_name, {})
        data = store.get(self.id)
        return _InMemoryDocSnapshot(self.id, data)

    def collection(self, sub_name: str) -> _InMemoryCollectionRef:
        key = f"{self.collection_name}/{self.id}/{sub_name}"
        return _InMemoryCollectionRef(key)


class _InMemoryQuery:
    def __init__(self, collection_name: str, filters: list | None = None, order_field: str | None = None, limit_n: int | None = None):
        self.collection_name = collection_name
        self.filters = filters or []
        self.order_field = order_field
        self.limit_n = limit_n

    def where(self, field: str, op: str, value: Any) -> _InMemoryQuery:
        new_filters = list(self.filters) + [(field, op, value)]
        return _InMemoryQuery(self.collection_name, new_filters, self.order_field, self.limit_n)

    def order_by(self, field: str, direction: str = "ASCENDING") -> _InMemoryQuery:
        return _InMemoryQuery(self.collection_name, self.filters, field, self.limit_n)

    def limit(self, count: int) -> _InMemoryQuery:
        return _InMemoryQuery(self.collection_name, self.filters, self.order_field, count)

    async def get(self) -> list[_InMemoryDocSnapshot]:
        store = _IN_MEMORY_STORE.setdefault(self.collection_name, {})
        docs = []
        for doc_id, data in list(store.items()):
            match = True
            for field, op, val in self.filters:
                doc_val = data.get(field)
                if op == "==" and doc_val != val:
                    match = False
                elif op == ">" and (doc_val is None or doc_val <= val):
                    match = False
                elif op == "<" and (doc_val is None or doc_val >= val):
                    match = False
            if match:
                docs.append(_InMemoryDocSnapshot(doc_id, data))

        if self.order_field:
            docs.sort(key=lambda d: (d.to_dict() or {}).get(self.order_field, 0))

        if self.limit_n:
            docs = docs[:self.limit_n]
        return docs

    async def stream(self):
        docs = await self.get()
        for doc in docs:
            yield doc


class _InMemoryCollectionRef(_InMemoryQuery):
    def __init__(self, collection_name: str):
        super().__init__(collection_name)

    def document(self, doc_id: str) -> _InMemoryDocRef:
        return _InMemoryDocRef(self.collection_name, doc_id)

    async def add(self, data: dict[str, Any]) -> tuple[Any, _InMemoryDocRef]:
        import uuid
        doc_id = str(uuid.uuid4())
        doc_ref = self.document(doc_id)
        await doc_ref.set(data)
        return None, doc_ref


class _InMemoryFirestoreClient:
    def collection(self, name: str) -> _InMemoryCollectionRef:
        return _InMemoryCollectionRef(name)

    def transaction(self) -> Any:
        class _Txn:
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
            def update(self, doc_ref, updates):
                store = _IN_MEMORY_STORE.setdefault(doc_ref.collection_name, {})
                if doc_ref.id in store:
                    store[doc_ref.id].update(updates)
                else:
                    store[doc_ref.id] = updates.copy()
            def set(self, doc_ref, data):
                store = _IN_MEMORY_STORE.setdefault(doc_ref.collection_name, {})
                store[doc_ref.id] = data.copy()
        return _Txn()


@lru_cache(maxsize=1)
def get_firestore_client() -> Any:
    settings = get_settings()

    if settings.is_development and not os.environ.get("USE_REAL_FIRESTORE"):
        logger.info("using_resilient_in_memory_firestore_store")
        return _InMemoryFirestoreClient()

    try:
        from google.cloud import firestore
        if settings.use_firestore_emulator:
            os.environ["FIRESTORE_EMULATOR_HOST"] = settings.firestore_emulator_host
        return firestore.AsyncClient(
            project=settings.gcp_project_id,
            database=settings.firestore_database,
        )
    except Exception as exc:
        logger.warning("firestore_client_init_failed_falling_back", error=str(exc))
        return _InMemoryFirestoreClient()


# ── Collection References ──────────────────────────────────────────────────────
INVESTIGATIONS_COLLECTION = "investigations"
AUTHORIZED_TARGETS_COLLECTION = "authorized_targets"
REPORTS_COLLECTION = "reports"


def investigations_ref() -> Any:
    return get_firestore_client().collection(INVESTIGATIONS_COLLECTION)


def authorized_targets_ref() -> Any:
    return get_firestore_client().collection(AUTHORIZED_TARGETS_COLLECTION)


def reports_ref() -> Any:
    return get_firestore_client().collection(REPORTS_COLLECTION)


def agent_events_ref(investigation_id: str) -> Any:
    return (
        get_firestore_client()
        .collection(INVESTIGATIONS_COLLECTION)
        .document(investigation_id)
        .collection("agent_events")
    )


def findings_ref(investigation_id: str) -> Any:
    return (
        get_firestore_client()
        .collection(INVESTIGATIONS_COLLECTION)
        .document(investigation_id)
        .collection("findings")
    )
