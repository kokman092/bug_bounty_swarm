"""
app/investigations/domain.py
─────────────────────────────
Investigation domain model and state machine.

The state machine is the single source of truth for valid transitions.
No code outside this module should set investigation status directly —
use StateMachine.transition() which validates before changing.

States:
  CREATED → AUTHORIZING → AUTHORIZED → QUEUED → RUNNING
    ├─ RUNNING → CANCELLING → CANCELLED
    ├─ RUNNING → FAILED → RETRYING → RUNNING (up to max_retries)
    ├─ RUNNING → FAILED (permanent, retries exhausted)
    └─ RUNNING → FINALIZING → COMPLETED

Terminal states: REJECTED, CANCELLED, FAILED (exhausted), COMPLETED
"""
from __future__ import annotations

from enum import Enum
from typing import ClassVar

from app.core.exceptions import InvalidStateTransitionError, InvestigationAlreadyTerminalError


class InvestigationStatus(str, Enum):
    """All possible investigation statuses."""
    CREATED     = "CREATED"
    AUTHORIZING = "AUTHORIZING"
    REJECTED    = "REJECTED"       # Terminal: target not authorized
    AUTHORIZED  = "AUTHORIZED"
    QUEUED      = "QUEUED"
    RUNNING     = "RUNNING"
    CANCELLING  = "CANCELLING"
    CANCELLED   = "CANCELLED"      # Terminal
    FAILED      = "FAILED"         # Terminal (when retries exhausted)
    RETRYING    = "RETRYING"
    FINALIZING  = "FINALIZING"
    COMPLETED   = "COMPLETED"      # Terminal


class InvestigationPhase(str, Enum):
    """Current active phase within a RUNNING investigation."""
    RECON          = "RECON"
    ATTACK_SURFACE = "ATTACK_SURFACE"
    LOOP           = "LOOP"
    REPORT         = "REPORT"
    DONE           = "DONE"


# ── Terminal states — no further transitions allowed ───────────────────────────

TERMINAL_STATES: frozenset[InvestigationStatus] = frozenset({
    InvestigationStatus.REJECTED,
    InvestigationStatus.CANCELLED,
    InvestigationStatus.FAILED,
    InvestigationStatus.COMPLETED,
})

# ── Allowed transitions ────────────────────────────────────────────────────────
# Each key is the current state; value is the set of states it may transition to.

_ALLOWED_TRANSITIONS: dict[InvestigationStatus, frozenset[InvestigationStatus]] = {
    InvestigationStatus.CREATED: frozenset({
        InvestigationStatus.AUTHORIZING,
        InvestigationStatus.FAILED,    # if DB write itself fails
    }),
    InvestigationStatus.AUTHORIZING: frozenset({
        InvestigationStatus.AUTHORIZED,
        InvestigationStatus.REJECTED,
        InvestigationStatus.FAILED,
    }),
    InvestigationStatus.AUTHORIZED: frozenset({
        InvestigationStatus.QUEUED,
        InvestigationStatus.FAILED,    # if task dispatch fails
    }),
    InvestigationStatus.QUEUED: frozenset({
        InvestigationStatus.RUNNING,
        InvestigationStatus.FAILED,    # if runner never picks up
    }),
    InvestigationStatus.RUNNING: frozenset({
        InvestigationStatus.FINALIZING,
        InvestigationStatus.CANCELLING,
        InvestigationStatus.FAILED,
        InvestigationStatus.RETRYING,
    }),
    InvestigationStatus.CANCELLING: frozenset({
        InvestigationStatus.CANCELLED,
        InvestigationStatus.FAILED,    # if cancel itself errors
    }),
    InvestigationStatus.RETRYING: frozenset({
        InvestigationStatus.RUNNING,
        InvestigationStatus.FAILED,    # if retry limit reached
    }),
    InvestigationStatus.FINALIZING: frozenset({
        InvestigationStatus.COMPLETED,
        InvestigationStatus.FAILED,
    }),
    # Terminal states have empty transition sets (defined below)
    InvestigationStatus.REJECTED:  frozenset(),
    InvestigationStatus.CANCELLED: frozenset(),
    InvestigationStatus.FAILED:    frozenset(),
    InvestigationStatus.COMPLETED: frozenset(),
}


class InvestigationStateMachine:
    """
    Validates and enforces investigation state transitions.

    Usage:
        machine = InvestigationStateMachine(current_status)
        new_status = machine.transition(InvestigationStatus.RUNNING)
        # new_status is the validated next status
        # Raises InvalidStateTransitionError if transition is not allowed
    """

    def __init__(self, current_status: InvestigationStatus) -> None:
        self.current_status = current_status

    def can_transition_to(self, target: InvestigationStatus) -> bool:
        """Return True if the transition from current to target is valid."""
        return target in _ALLOWED_TRANSITIONS.get(self.current_status, frozenset())

    def transition(self, target: InvestigationStatus) -> InvestigationStatus:
        """
        Validate and perform a state transition.

        Returns the new status if allowed.
        Raises InvestigationAlreadyTerminalError if in a terminal state.
        Raises InvalidStateTransitionError if the transition is not allowed.
        """
        if self.current_status in TERMINAL_STATES:
            raise InvestigationAlreadyTerminalError(
                investigation_id="<unknown>",
                status=self.current_status.value,
            )

        if not self.can_transition_to(target):
            raise InvalidStateTransitionError(
                current=self.current_status.value,
                attempted=target.value,
            )

        self.current_status = target
        return target

    def allowed_transitions(self) -> list[InvestigationStatus]:
        """Return all allowed transitions from the current state."""
        return list(_ALLOWED_TRANSITIONS.get(self.current_status, frozenset()))

    def is_terminal(self) -> bool:
        return self.current_status in TERMINAL_STATES

    def is_active(self) -> bool:
        return not self.is_terminal()
