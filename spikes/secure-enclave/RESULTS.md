# Results

Fill this in while working through [CHECKLIST.md](CHECKLIST.md). Pasting the JSON lines is fine.

## Test machine

| | |
|---|---|
| Date | 2026-11-20 |
| Mac model (`hwModel`) | **VirtualMac2,1 (a macOS VM)** |
| macOS version | 27.2.1 (26B131) |
| Touch ID | none (`biometryType: touchID`, but "Biometry is not enrolled", LAError -7) |
| Xcode / Swift version | not recorded |

> **Run 1 was on a VM.** Prompts were the password fallback. Secure Enclave is reported available,
> but it is the VM's virtual Secure Enclave. A2, A6 and E1 to E5 must be repeated on a physical Mac
> with Touch ID before the decision is final.

## 1. Environment

| Variant | Launches? | teamID | hardenedRuntime | entitlements | notes |
|---|---|---|---|---|---|
| V1 adhoc | built, not run yet | not set | no (adhoc, linker-signed) | none | |
| V2 appledev | yes | E89Q3796E9 | yes | none | Apple Development cert; signing identifier dev.farrier.spike |
| V3 devid | – | | | | no Developer ID Application certificate yet |
| V4 devid-kag | | | | | |
| V5 app | | | | | |
| V6 app-kag | | | | | |

## 2. Approach A core path

| Test | V1 | V2 (VM) | V3 | V5 | notes |
|---|---|---|---|---|---|
| A1 create, no prompt | | ✅ | | | 427-byte key blob |
| A2 sign, prompt appears | | ✅ (password) | | | `secondsInSign` 8.55. Prompt shows name: ? |
| A3 verify as user | | ✅ | | | the user-run verify in A8 showed `signatureValid: true` |
| A4 verify as root | | ✅ | | | `euid: 0`, `signatureValid: true`, `fingerprintMatches: true` |
| A5 tamper detected | | ✅ | | | `signatureValid: false` |
| A6 prompts on every signature | | ✅ | | | two signatures back to back: 4.79 s and 3.95 s |
| A7 cancel error (domain/code) | | ✅ | | | `com.apple.LocalAuthentication` **-2** (`LAError.userCancel`, "Canceled by user."). Nothing is signed. (The first attempt was approved by mistake.) |
| A8 expiry detected | | ✅ | | | ttl 5 s, verified after 6 s: `signatureValid: true`, `expired: true`, `ok: false` |

Screenshot of the prompt:

## 3. Approach A edge cases

| Test | Result | notes |
|---|---|---|
| E1 password fallback | ✅ on VM (V2) | no biometry enrolled, so the password prompt was used |
| E2 policies (userPresence / biometryAny / biometryCurrentSet / none) | partial | `none` control on the VM: no prompt, `secondsInSign: 0` (324-byte blob, against 427 for userPresence). Biometry policies need Touch ID. |
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
