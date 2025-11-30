"""Reference funds transfer implementation."""

from __future__ import annotations

from tg_code.funds_transfer_starter import InMemoryRepo


def transfer_funds(
    current_user_id: str, source_account_id: str, target_account_id: str, amount: float, repo: InMemoryRepo
) -> None:
    if amount <= 0:
        raise Exception("amount must be positive")

    # Ownership check
    if repo.get_account_owner(source_account_id) != current_user_id:
        raise Exception("forbidden")

    # Balance check
    if repo.get_balance(source_account_id) < amount:
        raise Exception("insufficient_funds")

    with repo.begin_transaction():
        repo.debit(source_account_id, amount)
        repo.credit(target_account_id, amount)
