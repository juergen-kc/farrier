# Results

Fill this in while working through [CHECKLIST.md](CHECKLIST.md). Pasting JSON lines is fine.

## Test machine

| | |
|---|---|
| Date | |
| Mac model / VM | |
| macOS version | |
| Signing identity | |
| Compile fixes needed (X0) | |

## 1. Registration

| Test | Result | notes |
|---|---|---|
| X1 info | | |
| X2 register → requiresApproval, Settings opens | | name and icon shown: |
| X3 enabled after approval | | |
| X4 launchctl print | | |
| X5 works from Terminal / needs `open` | | |

Screenshot of the Login Items entry:

## 2. XPC and pinning

| Test | Result | notes |
|---|---|---|
| X6 ping (euid 0, identifier) | | |
| X7 ad hoc client rejected | | error domain/code: |
| X8 same team, other identifier rejected | | |
| X9 client rejects unexpected helper | | |
| X10 same binary outside the bundle | | |

## 3. Console-session check

| Test | sessionOK | bits | graphic | remote | notes |
|---|---|---|---|---|---|
| X11 local | | | | | |
| X12 sudo | | | | | |
| X13 SSH | | | | | |
| X14 Claude Code | | | | | |

## 4. Enrollment

| Test | Result | notes |
|---|---|---|
| X15 key-create, no prompt | | |
| X16 key-acl integrityOK | | |
| X17 enroll: admin dialog | | dialog names: ; loading the key prompted? |
| X18 key file root:wheel 0644 | | |
| X19 cancel → refused | | authStatus: |
| X20 SSH enroll refused before dialog | | |
| X21 authorizationdb rule | | |

## 5. Approval round trip

| Test | Result | notes |
|---|---|---|
| X22 approve | | |
| X23 replay refused | | |
| X24 tamper refused | | |
| X25 expiry refused | | expired / unknown nonce: |
| X26 SSH approve refused | | |
| X27 attacker rejected | | |

## 6. Integrity check

| Test | Result | notes |
|---|---|---|
| X28 "Always Allow" detected | | |

## 7. Updates

| Test | Result | notes |
|---|---|---|
| X29 status after update | | |
| X29 new helper answers | | kickstart needed? |
| X29 key and enrollment kept | | |

## Conclusions

- Registration and update behaviour:
- Pinning works in both directions: [ ]
- Console-session check method confirmed: [ ] `SessionGetInfo` / [ ] needs an alternative
- Enrollment with admin authorization: [ ]
- Approval round trip: [ ]
- Integrity check: [ ]

ARCHITECTURE.md and THREAT_MODEL.md updated: [ ]
