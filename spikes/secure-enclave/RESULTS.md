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
| V1 adhoc | yes | (none) | no (adhoc, linker-signed) | none | signing identifier `se-spike` |
| V2 appledev | yes | E89Q3796E9 | yes | none | Apple Development cert; signing identifier dev.farrier.spike |
| V3 devid | – | | | | no Developer ID Application certificate yet |
| V4 devid-kag | | | | | |
| V5 app | | | | | |
| V6 app-kag | | | | | |

## 2. Approach A core path

| Test | V1 | V2 (VM) | V3 | V5 | notes |
|---|---|---|---|---|---|
| A1 create, no prompt | ✅ | ✅ | | | 427-byte key blob |
| A2 sign, prompt appears | ✅ (password) | ✅ (password) | | | V2 took 8.55 s, V1 5.13 s. The prompt names the **executable file name** ("v2-appledev"); see below |
| A3 verify as user | | ✅ | | | the user-run verify in A8 showed `signatureValid: true` |
| A4 verify as root | ✅ | ✅ | | | `euid: 0`, `signatureValid: true`, `fingerprintMatches: true` |
| A5 tamper detected | | ✅ | | | `signatureValid: false` |
| A6 prompts on every signature | | ✅ | | | two signatures back to back: 4.79 s and 3.95 s |
| A7 cancel error (domain/code) | | ✅ | | | `com.apple.LocalAuthentication` **-2** (`LAError.userCancel`, "Canceled by user."). Nothing is signed. (The first attempt was approved by mistake.) |
| A8 expiry detected | | ✅ | | | ttl 5 s, verified after 6 s: `signatureValid: true`, `expired: true`, `ok: false` |

Prompt (V2, VM, password fallback). The icon is the generic "exec" icon with a lock:

> **v2-appledev is trying to approve a Farrier plan (spike test, 3 items, 1.2 GB).**
> Enter the password for the user "juergen" to continue with v2-appledev.

- The first sentence is `"<executable file name> is trying to " + localizedReason`. Farrier controls the reason text.
- The name comes from the file name, not the signing identifier or the bundle name. V5 should show whether
  an app bundle changes this.

## 3. Approach A edge cases

| Test | Result | notes |
|---|---|---|
| E1 password fallback | ✅ on VM (V2) | no biometry enrolled, so the password prompt was used |
| E2 policies (userPresence / biometryAny / biometryCurrentSet / none) | partial | `none` control on the VM: no prompt, `secondsInSign: 0` (324-byte blob, against 427 for userPresence). Biometry policies need Touch ID. |
| E3 enrollment change | | |
| E4 locked screen | ✅ signed after unlock (26.3 s) | where the prompt appeared: ? |
| E5 SSH session | | **prompt on console?** |
| E6 started by Claude Code | | parent: |
| E7 root signs with user key | ❌ as expected | the prompt appeared, juergen's password was not accepted, and the result was LAError -2. Prompted user: ? |
| E8 other user | | |
| E9 other Mac | | |
| E10 quarantined download | | |

## 4. Approach B

| Test | V3 | V4 | V5 | V6 | notes |
|---|---|---|---|---|---|
| B1 create, no group | | | | | |
| B2 create, with group | – | | – | | |
| B3 sign + verify | | | | | |

## 4b. Approach C

| Test | V2 | V3 | V5 | notes |
|---|---|---|---|---|
| C1 create, no dialogs | | | | |
| C2 trusted binary: only the user-presence prompt | | | | |
| C3 V1 (ad hoc) gets a keychain dialog; Deny gives an error | – | – | – | osstatus: |
| C4 `security` tool gets a dialog | | | | |
| C5 V2b (same team, other identifier) gets a dialog | | – | – | |
| C6 Allow (once), then user-presence prompt, then signs | | | | |
| C7 over SSH | | | | |

Screenshot of the keychain dialog (C3):

## Findings

**F1: An Approach A key is not tied to the calling code's identity.** (V1 ad hoc and V2 Apple Development both work.)
Any process running as the same user can read the key blob (mode 0600, owned by the user) and request a
signature. It controls both the name in the prompt (its file name) and the reason text. So it could get
approval for a **different** plan hash than the prompt describes. User presence is still required, so it is
never silent, but the prompt can lie. The threat model lists same-user processes as in scope
(THREAT_MODEL.md, Actors; T-2/T-3), and the approval guards root-tier helper actions.

Options to evaluate:
- **Approach B** (data-protection keychain): ties use of the key to the code signature, but needs an entitlement.
- **Approach C** (added to the spike, see 4b): keep the CryptoKit key, but store its blob in the **login (file-based)
  keychain** as a generic password, with an ACL that trusts only Farrier's designated requirement. No
  entitlement should be needed. Another process reading it triggers a keychain access prompt.
- Accept the risk, and state it as residual risk in T-3.

## Decision

- [ ] Preferred design: Approach C (variant: ___ )
- [ ] Approach A, with F1 accepted as residual risk
- [ ] Approach B with entitlement
- [ ] Fallback design

Additional mitigations needed (for example, from E5):

THREAT_MODEL.md and ARCHITECTURE.md updated: [ ]
