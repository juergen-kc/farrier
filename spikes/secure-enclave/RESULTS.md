# Results

Fill this in while working through [CHECKLIST.md](CHECKLIST.md). Pasting the JSON lines is fine.

## Test machine

| | |
|---|---|
| Date | |
| Mac model (`hwModel`) | |
| macOS version | |
| Touch ID | built-in / Magic Keyboard / none |
| Xcode / Swift version | |

## 1. Environment

| Variant | Launches? | teamID | hardenedRuntime | entitlements | notes |
|---|---|---|---|---|---|
| V1 adhoc | | | | | |
| V2 appledev | | | | | |
| V3 devid | | | | | |
| V4 devid-kag | | | | | |
| V5 app | | | | | |
| V6 app-kag | | | | | |

## 2. Approach A core path

| Test | V1 | V3 | V5 | notes |
|---|---|---|---|---|
| A1 create, no prompt | | | | |
| A2 sign, prompt appears | | | | prompt shows name: |
| A3 verify as user | | | | |
| A4 verify as root | | | | |
| A5 tamper detected | | | | |
| A6 prompts on every signature | | | | |
| A7 cancel error (domain/code) | | | | |
| A8 expiry detected | | | | |

Screenshot of the prompt:

## 3. Approach A edge cases

| Test | Result | notes |
|---|---|---|
| E1 password fallback | | |
| E2 policies (userPresence / biometryAny / biometryCurrentSet / none) | | |
| E3 enrollment change | | |
| E4 locked screen | | |
| E5 SSH session | | **prompt on console?** |
| E6 started by Claude Code | | parent: |
| E7 root signs with user key | | |
| E8 other user | | |
| E9 other Mac | | |
| E10 quarantined download | | |

## 4. Approach B

| Test | V3 | V4 | V5 | V6 | notes |
|---|---|---|---|---|---|
| B1 create, no group | | | | | |
| B2 create, with group | – | | – | | |
| B3 sign + verify | | | | | |

## Decision

- [ ] Preferred design: Approach A (variant: ___ )
- [ ] Approach B with entitlement
- [ ] Fallback design

Additional mitigations needed (for example, from E5):

THREAT_MODEL.md and ARCHITECTURE.md updated: [ ]
