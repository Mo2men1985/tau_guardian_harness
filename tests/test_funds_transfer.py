import os
import sys
ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import pytest
from tg_code.funds_transfer_solution import transfer_funds
from tg_code.funds_transfer_starter import InMemoryRepo


def setup_repo():
    repo = InMemoryRepo()
    repo.add_account("A", "user1", 100.0)
    repo.add_account("B", "user2", 50.0)
    return repo


def test_successful_transfer():
    repo = setup_repo()
    transfer_funds("user1", "A", "B", 25.0, repo)
    assert repo.get_balance("A") == pytest.approx(75.0)
    assert repo.get_balance("B") == pytest.approx(75.0)


def test_cannot_overdraw():
    repo = setup_repo()
    with pytest.raises(Exception):
        transfer_funds("user1", "A", "B", 1000.0, repo)


def test_cannot_transfer_from_foreign_account():
    repo = setup_repo()
    with pytest.raises(Exception):
        transfer_funds("user2", "A", "B", 10.0, repo)


def test_cannot_transfer_non_positive_amount():
    repo = setup_repo()
    with pytest.raises(Exception):
        transfer_funds("user1", "A", "B", 0.0, repo)
