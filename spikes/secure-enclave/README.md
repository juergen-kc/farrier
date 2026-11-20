# Spike: approval with a Secure Enclave key

This spike decides the approval design in [THREAT_MODEL.md, T-3](../../docs/THREAT_MODEL.md#t-3-approval-forgery).

## The question

Can a **Developer ID–signed** Farrier binary, with **no provisioning profile**:

1. create a P-256 key in the Secure Enclave that needs **user presence** (Touch ID, or the login
   password as fallback) **every time it signs**,
2. sign a plan-approval payload with it, and
3. have a **root** process verify that signature with only the public key?

If yes, the root helper can verify approvals itself. Then a compromised user process can't approve a
destructive plan without the user's finger.

## The three approaches tested

| | Approach A | Approach B | Approach C |
|---|---|---|---|
| API | CryptoKit `SecureEnclave.P256.Signing.PrivateKey` | Security `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` | Same key as A |
| Where the key lives | An encrypted blob in a file. Only this Mac's Secure Enclave can use it. | A permanent item in the data-protection keychain | A's blob, stored in the **login keychain** with an access list that trusts only the creating binary |
| Entitlements expected | none | `keychain-access-groups`, which probably needs a profile | none (file-based keychain) |
| Who can use the key | **any process running as the user** (finding F1) | only code with the access group | only the trusted binary; others get a keychain dialog |

Approach C was added after finding F1 (see RESULTS.md). One limit applies to C as well: an attacker can still
run the **genuine** Farrier binary with arguments of their choosing. So in the real product, the prompt text
must be derived from the plan **inside** Farrier, never taken from an argument. In this spike, `--reason` is an
argument, but only for testing.

Approach A is believed to work for command-line tools without entitlements. For example, as far as
we know, `age-plugin-se` ships a Homebrew CLI built this way. **Verify this, don't assume it.**

## The payload

```
"farrier-plan-approval-v1" 0x00 | planHash (32) | nonce (32, issued by the helper) | expiresAt (int64 BE)
```

The signature is ECDSA P-256 over SHA-256, DER-encoded (X9.62). All three approaches produce the same format.

## Files

```
Package.swift                 no dependencies; macOS 14+
Sources/se-spike/
  main.swift                  CLI: info, a-*, b-*, c-*, verify
  ApproachA.swift             CryptoKit Secure Enclave key, blob in a file
  ApproachB.swift             keychain-backed Secure Enclave key
  ApproachC.swift             A's key, with the blob in the login keychain behind an access list
  Approval.swift              payload format + verifier (the helper's side)
  Info.swift                  signing, session and biometry facts
  Support.swift               output, errors, policies, helpers
scripts/build-variants.sh     builds the signing variants V1, V2, V2b and V3 to V6
support/                      Info.plist for the app-bundle variants; entitlement template
CHECKLIST.md                  the test procedure
RESULTS.md                    where results are recorded
```

> Approaches A and B compiled cleanly on macOS 27.2.1 on the first try. `ApproachC.swift` was added afterwards,
> without a macOS toolchain, so it hasn't been compiled yet. Expect deprecation warnings from the
> file-based keychain APIs (`SecAccessCreate`, `SecTrustedApplicationCreateFromPath`).
