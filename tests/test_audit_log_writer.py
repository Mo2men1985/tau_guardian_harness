import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from tg_code.audit_log_writer_solution import InMemoryAuditRepo, write_audit_log


def test_writes_two_events_per_call():
    repo = InMemoryAuditRepo()
    write_audit_log(repo, "u1", "login")
    assert len(repo.events) == 2
    types = {e["type"] for e in repo.events}
    assert "USER_ACTION" in types
    assert "AUDIT_TRAIL" in types


def test_appends_on_multiple_calls():
    repo = InMemoryAuditRepo()
    write_audit_log(repo, "u1", "login")
    write_audit_log(repo, "u1", "logout")
    assert len(repo.events) == 4

