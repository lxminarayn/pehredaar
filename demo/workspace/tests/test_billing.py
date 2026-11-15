from decimal import Decimal

import pytest
from src.billing import calculate_total


@pytest.mark.parametrize(
    ("base", "prorated", "expected"),
    [
        ("10.00", "0.00", "10.00"),
        ("20.00", "0.00", "20.00"),
        ("30.00", "0.00", "30.00"),
        ("40.00", "0.00", "40.00"),
        ("50.00", "0.00", "50.00"),
        ("60.00", "0.00", "60.00"),
        ("70.00", "0.00", "70.00"),
        ("80.00", "0.00", "80.00"),
        ("90.00", "0.00", "90.00"),
        ("100.00", "0.00", "100.00"),
        ("110.00", "0.00", "110.00"),
        ("100.00", "15.00", "115.00"),
    ],
)
def test_calculate_total(base: str, prorated: str, expected: str) -> None:
    assert calculate_total(Decimal(base), Decimal(prorated)) == Decimal(expected)
