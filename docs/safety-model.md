# Safety model

SecSuite is intentionally defensive and fail-closed.

## Design rules
- only passive collection and review
- no state changes on assessed targets
- policy-controlled execution
- denied categories are enforced in code by the Safety module

The Safety module blocks disallowed actions by design.
