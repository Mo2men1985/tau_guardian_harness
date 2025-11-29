from contextlib import contextmanager


class InMemoryRepo:
    def __init__(self):
        self._owners = {}
        self._balances = {}

    def add_account(self, account_id: str, owner_id: str, balance: float):
        self._owners[account_id] = owner_id
        self._balances[account_id] = balance

    def get_account_owner(self, account_id: str) -> str:
        return self._owners[account_id]

    def get_balance(self, account_id: str) -> float:
        return self._balances[account_id]

    def debit(self, account_id: str, amount: float) -> None:
        self._balances[account_id] -= amount

    def credit(self, account_id: str, amount: float) -> None:
        self._balances[account_id] += amount

    def begin_transaction(self):
        @contextmanager
        def tx():
            # Snapshot balances for rollback on error
            snapshot = dict(self._balances)
            try:
                yield
            except Exception:
                self._balances = snapshot
                raise

        return tx()


def transfer_funds(
    current_user_id: str,
    source_account_id: str,
    target_account_id: str,
    amount: float,
    repo: InMemoryRepo,
) -> None:
    if amount <= 0:
        raise ValueError("Transfer amount must be positive.")

    try:
        owner = repo.get_account_owner(source_account_id)
    except KeyError:
        raise ValueError("Source account does not exist.")

    if owner != current_user_id:
        raise PermissionError("User not authorized to transfer from this account.")

    if source_account_id == target_account_id:
        raise ValueError("Source and target accounts must be different.")

    try:
        source_balance = repo.get_balance(source_account_id)
    except KeyError:
        raise ValueError("Source account does not exist.")

    if source_balance < amount:
        raise ValueError("Insufficient funds in source account.")

    # Ensure target account exists before starting transaction
    try:
        repo.get_account_owner(target_account_id)
    except KeyError:
        raise ValueError("Target account does not exist.")

    with repo.begin_transaction():
        # Re-check balance inside transaction to reduce race conditions
        current_balance = repo.get_balance(source_account_id)
        if current_balance < amount:
            raise ValueError("Insufficient funds in source account.")
        repo.debit(source_account_id, amount)
        repo.credit(target_account_id, amount)
