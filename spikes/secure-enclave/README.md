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

## The two approaches tested

| | Approach A (preferred) | Approach B |
|---|---|---|
| API | CryptoKit `SecureEnclave.P256.Signing.PrivateKey` | Security `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` |
| Where the key lives | An encrypted blob in a file. Only this Mac's Secure Enclave can use it. | A permanent item in the data-protection keychain |
| Entitlements expected | none | `keychain-access-groups`, which probably needs a profile |

Approach A is believed to work for command-line tools without entitlements. For example, as far as
we know, `age-plugin-se` ships a Homebrew CLI built this way. **Verify this, don't assume it.**

## The payload

```
"farrier-plan-approval-v1" 0x00 | planHash (32) | nonce (32, issued by the helper) | expiresAt (int64 BE)
```

The signature is ECDSA P-256 over SHA-256, DER-encoded (X9.62). Both approaches produce the same format.

## Files

```
Package.swift                 no dependencies; macOS 14+
Sources/se-spike/
  main.swift                  CLI: info, a-create, a-sign, b-create, b-sign, b-delete, verify
  ApproachA.swift             CryptoKit Secure Enclave key, blob in a file
  ApproachB.swift             keychain-backed Secure Enclave key
  Approval.swift              payload format + verifier (the helper's side)
  Info.swift                  signing, session and biometry facts
  Support.swift               output, errors, policies, helpers
scripts/build-variants.sh     builds the signing variants V1 to V6
support/                      Info.plist for the app-bundle variants; entitlement template
CHECKLIST.md                  the test procedure
RESULTS.md                    where results are recorded
```

> This code has not been compiled yet. It was written without a macOS toolchain, so step 0 of the
> checklist is to build it and fix any compile errors.
