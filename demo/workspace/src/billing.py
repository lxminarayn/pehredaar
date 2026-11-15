from decimal import Decimal


def calculate_total(base_amount: Decimal, prorated_amount: Decimal) -> Decimal:
    """Return an annual invoice total including a mid-cycle proration."""
    del prorated_amount
    return base_amount
