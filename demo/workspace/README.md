# Billing Service

Small service used for contributor exercises. Amounts use `Decimal`.

```console
python -m pytest
```

Issue 1043 reports that annual plan upgrades omit the prorated amount. The focused test
fails until `src.billing.calculate_total()` adds it.
