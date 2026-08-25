"""
tests/unit/test_state_machine.py
────────────────────────────────
Unit tests for the investigation state machine.
"""
import pytest

from app.core.exceptions import InvalidStateTransitionError, InvestigationAlreadyTerminalError
from app.investigations.domain import (
    InvestigationStateMachine,
    InvestigationStatus,
    TERMINAL_STATES,
)


class TestStateMachine:

    def test_happy_path_lifecycle(self):
        """CREATED -> AUTHORIZING -> AUTHORIZED -> QUEUED -> RUNNING -> FINALIZING -> COMPLETED"""
        sm = InvestigationStateMachine(InvestigationStatus.CREATED)
        assert sm.transition(InvestigationStatus.AUTHORIZING) == InvestigationStatus.AUTHORIZING
        assert sm.transition(InvestigationStatus.AUTHORIZED) == InvestigationStatus.AUTHORIZED
        assert sm.transition(InvestigationStatus.QUEUED) == InvestigationStatus.QUEUED
        assert sm.transition(InvestigationStatus.RUNNING) == InvestigationStatus.RUNNING
        assert sm.transition(InvestigationStatus.FINALIZING) == InvestigationStatus.FINALIZING
        assert sm.transition(InvestigationStatus.COMPLETED) == InvestigationStatus.COMPLETED
        assert sm.is_terminal() is True

    def test_rejection_branch(self):
        """CREATED -> AUTHORIZING -> REJECTED"""
        sm = InvestigationStateMachine(InvestigationStatus.CREATED)
        sm.transition(InvestigationStatus.AUTHORIZING)
        assert sm.transition(InvestigationStatus.REJECTED) == InvestigationStatus.REJECTED
        assert sm.is_terminal() is True

    def test_cancellation_branch(self):
        """RUNNING -> CANCELLING -> CANCELLED"""
        sm = InvestigationStateMachine(InvestigationStatus.RUNNING)
        assert sm.transition(InvestigationStatus.CANCELLING) == InvestigationStatus.CANCELLING
        assert sm.transition(InvestigationStatus.CANCELLED) == InvestigationStatus.CANCELLED
        assert sm.is_terminal() is True

    def test_retry_branch(self):
        """RUNNING -> RETRYING -> RUNNING"""
        sm = InvestigationStateMachine(InvestigationStatus.RUNNING)
        assert sm.transition(InvestigationStatus.RETRYING) == InvestigationStatus.RETRYING
        assert sm.transition(InvestigationStatus.RUNNING) == InvestigationStatus.RUNNING

    def test_cannot_transition_from_terminal_completed(self):
        sm = InvestigationStateMachine(InvestigationStatus.COMPLETED)
        with pytest.raises(InvestigationAlreadyTerminalError):
            sm.transition(InvestigationStatus.RUNNING)

    def test_cannot_transition_from_terminal_failed(self):
        sm = InvestigationStateMachine(InvestigationStatus.FAILED)
        with pytest.raises(InvestigationAlreadyTerminalError):
            sm.transition(InvestigationStatus.AUTHORIZED)

    def test_illegal_jump_created_to_completed(self):
        sm = InvestigationStateMachine(InvestigationStatus.CREATED)
        with pytest.raises(InvalidStateTransitionError):
            sm.transition(InvestigationStatus.COMPLETED)

    def test_illegal_jump_queued_to_finalizing(self):
        sm = InvestigationStateMachine(InvestigationStatus.QUEUED)
        with pytest.raises(InvalidStateTransitionError):
            sm.transition(InvestigationStatus.FINALIZING)

    def test_all_terminal_states_recognized(self):
        for state in TERMINAL_STATES:
            sm = InvestigationStateMachine(state)
            assert sm.is_terminal() is True
            assert sm.is_active() is False
