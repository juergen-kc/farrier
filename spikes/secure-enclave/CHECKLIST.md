# Test checklist

Run this on a real Mac. Record every result in [RESULTS.md](RESULTS.md); pasting the JSON lines is enough.
Each command prints one JSON line. `"ok": true` means it succeeded.

**Time needed:** about 45 minutes for the core path (sections 0 to 4), plus about 30 minutes for the rest.

## Prerequisites

- [ ] A Mac with Touch ID (built-in, or a Magic Keyboard with Touch ID), macOS 14 or later.
      Record the macOS version. Repeat the core path on macOS 15 and 26 if you can.
- [ ] Xcode 16+ or the Command Line Tools (`xcode-select -p`)
- [ ] A **Developer ID Application** certificate in your login keychain:
      `security find-identity -v -p codesigning`
- [ ] Optional: an Apple Development certificate (for V2)
- [ ] Optional: a notarytool profile (`xcrun notarytool store-credentials`), needed for section 7

```bash
cd spikes/secure-enclave
```

```bash
export DEVID_IDENTITY="Developer ID Application: Juergen Klaassen (TEAMID)"
```

```bash
export TEAMID=XXXXXXXXXX
```

## 0. Build

- [ ] `swift build -c release` compiles. Fix compile errors first. This code was written without a compiler.
- [ ] `./scripts/build-variants.sh` produces the variants in `out/`:

| Variant | What it is |
|---|---|
| V1 `out/v1-adhoc` | As built (linker-signed, ad hoc) |
| V2 `out/v2-appledev` | Apple Development (optional) |
| V3 `out/v3-devid` | Developer ID, hardened runtime, bare binary, **no entitlements** (the real-world CLI case) |
| V4 `out/v4-devid-kag` | V3 + `keychain-access-groups` entitlement, no profile |
| V5 `out/v5-FarrierSpike.app/Contents/MacOS/se-spike` | Developer ID app bundle (Farrier's real packaging) |
| V6 `out/v6-FarrierSpike-kag.app/Contents/MacOS/se-spike` | V5 + `keychain-access-groups` entitlement, no profile |

To repeat a test per variant, set `S` to the variant's binary path, for example:

```bash
S=out/v3-devid
```

## 1. Environment (all variants)

- [ ] `$S info`. Record `teamID`, `adhoc`, `hardenedRuntime`, `entitlements`, `secureEnclaveAvailable`,
      `biometryType` and `canBiometrics`.
- [ ] **V4 and V6: does the binary launch at all?** If it dies with `Killed: 9`, macOS (AMFI) rejected an
      entitlement that has no backing profile. Record it, and look in Console.app for `amfid` or
      `taskgated` messages.

## 2. Approach A core path (V1, V3, V5 at minimum)

Use a separate key per variant: `K=/tmp/farrier-$(basename $S).key`

- [ ] **A1 create:** `$S a-create --key $K`, then expect `ok: true`. **No prompt** should appear when creating.
- [ ] **A2 sign:** `$S a-sign --key $K --out /tmp/appr.json`. Expect:
  - [ ] a Touch ID prompt **appears**
  - [ ] the prompt shows the reason text. **Take a screenshot.** Record which name the prompt shows
        (binary name, bundle name, or something else).
  - [ ] after you approve, `ok: true` and `secondsInSign` above about 0.5. A value of about 0 means no prompt was shown, which is a **FAIL**.
- [ ] **A3 verify as user:** `$S verify --pub $K.pub --approval /tmp/appr.json`, then expect `ok: true`.
- [ ] **A4 verify as root (the helper's view):** `sudo $S verify --pub $K.pub --approval /tmp/appr.json`, then
      expect `ok: true` and `euid: 0`.
- [ ] **A5 tamper:** `$S verify --pub $K.pub --approval /tmp/appr.json --tamper`, then expect
      `signatureValid: false`.
- [ ] **A6 no reuse:** run `a-sign` twice in a row, within 5 seconds. **Both** runs must prompt.
- [ ] **A7 cancel:** run `a-sign` and click Cancel. Expect `ok: false`. Record the error domain and code.
- [ ] **A8 expiry:** `$S a-sign --key $K --ttl 5 --out /tmp/appr-exp.json`, wait 6 seconds, then verify.
      Expect `signatureValid: true` and `expired: true`.

**Decision point.** If A1 to A6 pass on **V3 and V5**, the preferred design works. Continue with section 3
to learn its edge cases. If they fail on V3 and V5 but pass on V1 or V2, record the exact error. The
problem is then signing-related, so go to section 4 next.

## 3. Approach A edge cases (V5, or V3 if V5 isn't available)

- [ ] **E1 password fallback:** close the lid with an external display, or disconnect the Touch ID
      keyboard, then sign. Expect a **password** prompt, and that signing succeeds.
- [ ] **E2 policy comparison:** create keys with `--policy biometryAny`, `biometryCurrentSet` and `none`.
      Sign with each. `none` must **not** prompt. That's the control. Record the behaviour of each.
- [ ] **E3 enrollment change (optional, slow):** with a `biometryCurrentSet` key, add a fingerprint in
      System Settings, then sign. Expect failure (key invalidated). Do the same with a `userPresence` key,
      which is expected to still work. Remove the test fingerprint afterwards.
- [ ] **E4 locked screen:** run `sleep 10; $S a-sign --key $K` and lock the screen during the sleep. Record
      what happens: it fails, it waits, or a prompt appears after unlock.
- [ ] **E5 SSH session (important):** from another machine, `ssh` into this Mac and run `a-sign`.
      Record whether it fails, or **whether a prompt appears on the Mac's screen**. A prompt on the
      console caused by a remote shell is a threat-model finding: a remote attacker could trigger a prompt
      that the person at the desk approves without knowing what it is.
- [ ] **E6 started by an AI agent:** in Claude Code, ask it to run
      `$S a-sign --key $K --reason "approve test plan from agent"`.
      Record that the prompt appears, the parent process (`$S info` run the same way shows `parent`), and
      that approval or cancel is reported back correctly. This approximates how an MCP server is started.
- [ ] **E7 root can't sign with the user's key:** `sudo $S a-sign --key $K`. Record the result.
      Information only, since root attackers are out of scope.
- [ ] **E8 another user:** copy `$K` to a second macOS user account and sign there. Expect failure.
- [ ] **E9 another Mac (optional):** copy `$K` to another Mac and sign. Expect failure.
- [ ] **E10 a quarantined download:** `xattr -w com.apple.quarantine "0081;$(printf %x $(date +%s));Safari;" <V5 app>`,
      then run the binary inside it. Record whether Gatekeeper blocks it. If V5 was notarized, the result
      should be "allowed".

## 4. Approach B (V3, V4, V5, V6)

- [ ] **B1 without access group:** `$S b-create --label t1`. Expect V3 and V5 to fail with `osstatus -34018`
      (errSecMissingEntitlement). Record the actual result.
- [ ] **B2 with access group:** on V4 and V6 only, and only if they launched:
      `$S b-create --label t2 --access-group $TEAMID.dev.farrier.spike`
- [ ] **B3 sign and verify:** if B1 or B2 succeeded, run
      `$S b-sign --label <label> --out /tmp/appr-b.json`, then
      `sudo $S verify --pub /tmp/appr-b.json.pub --approval /tmp/appr-b.json`. Expect a prompt on sign, and `ok: true` on verify.
- [ ] **B4 clean up:** `$S b-delete --label t1`, then the same for `t2`.

## 5. Clean up

- [ ] `rm /tmp/farrier-*.key* /tmp/appr*.json`
- [ ] Delete any Approach B keys (B4).
- [ ] Remove any fingerprint added for E3.

## 6. Decide

Fill in the decision at the bottom of RESULTS.md:

| Outcome | Decision |
|---|---|
| A passes on V3 **and** V5 | **Preferred design.** CryptoKit Secure Enclave key, blob in `~/Library/Application Support/Farrier/`, public key registered with the helper. |
| A passes on V5 only | Same design. The CLI must run from inside the app bundle (it does in the Homebrew cask anyway). |
| A fails, B passes on V6 | Ship an app bundle with an entitlement. Investigate whether a Developer ID provisioning profile is needed. |
| Both fail | **Fallback design.** LocalAuthentication runs in the signed client, and the helper trusts the client's code signature. Update the residual risk in THREAT_MODEL.md, T-3. |
| E5 shows a prompt from SSH | Add a mitigation either way: the helper refuses approvals whose session is not the console session. |

## 7. Notarization (optional, but do it before v0.1)

- [ ] `NOTARY_PROFILE=… ./scripts/build-variants.sh`. V5 notarizes and staples successfully.
- [ ] Repeat A2 and E10 with the notarized V5.

## Follow-ups this spike doesn't cover

- How the helper registers the public key in the first place. Enrollment has to be approved by an admin,
  not just by the user process, or an attacker could enroll their own key. This belongs in the
  `SMAppService` spike.
- An MCP server launched by a GUI client (for example Claude Desktop) rather than from a terminal. Test
  this in the Swift MCP SDK spike, using the same `a-sign` call from inside a tool.
