# Test checklist

Run on the macOS VM first (the Apple Development certificate is fine), then repeat the core path with Developer ID
on a physical Mac. Each command prints one JSON line. Record the results in [RESULTS.md](RESULTS.md).

**Time needed:** about 60 minutes.

In keychain dialogs, **never click "Always Allow"**, except in test X28, which is about exactly that.

## 0. Build and install

```bash
cd spikes/smappservice-xpc
```

```bash
export SIGN_IDENTITY="Apple Development: Jurgen Klaaben (U366MAP9SE)"
```

```bash
./scripts/build-app.sh
```

```bash
sudo rm -rf /Applications/FarrierSpike.app && sudo ditto out/FarrierSpike.app /Applications/FarrierSpike.app && sudo chown -R root:wheel /Applications/FarrierSpike.app
```

```bash
cd ~/Downloads/farrier/farrier/spikes/smappservice-xpc   # A and O below depend on this directory
F=/Applications/FarrierSpike.app/Contents/MacOS/farrier-spike; A=$PWD/out/attacker-adhoc; O=$PWD/out/attacker-other-id
```

- [ ] **X0 build:** it compiles. Fix compile errors first, since this was written without a compiler. Record any fixes.
- [ ] Optionally, keep the helper log open in a second Terminal window:

```bash
tail -f /Library/Logs/farrier-spike-helper.log
```

## 1. Registration (SMAppService)

- [ ] **X1:** `$F info`. Record `identifier` (expect `dev.farrier.spike.app`), `teamID`, `bundleID`, and `daemonStatus` (expect `notRegistered`).
- [ ] **X2 register:** `$F register`. Expect `requiresApproval`, and System Settings should open on Login Items & Extensions.
      Record: was there a notification ("Background Items Added")? What name and icon does the entry show? Is it
      listed under the app, the developer, or something else? **Take a screenshot.** Then turn it on (it will ask for admin credentials).
- [ ] **X3:** `$F status`. Expect `enabled`.
- [ ] **X4:** `sudo launchctl print system/dev.farrier.spike.helper | head -30`. Record `state` and `program`.
      It is normal that the helper isn't running yet, because launchd starts it on demand.
- [ ] **X5 launched by the CLI (not by Finder):** X2 ran the binary straight from Terminal. If registration
      failed there with an error, try it through LaunchServices instead, and record which way works:

```bash
open -W --stdout /tmp/fs-out.txt --stderr /tmp/fs-err.txt /Applications/FarrierSpike.app --args register; cat /tmp/fs-out.txt
```

## 2. XPC and code-signing pinning

- [ ] **X6 ping:** `$F ping`. Expect `ok: true`, `helperEuid: 0`, `helperIdentifier: dev.farrier.spike.helper`, and
      `pinnedHelper: true`. The log should show "starting …" and "connection from pid=…".
- [ ] **X7 ad hoc client:** `$A ping`. Expect **rejection**: `ok: false` with an `xpcError`. Record the domain, code, and
      message. The helper must not have answered. Its log shows the connection, then "invalidated".
- [ ] **X8 same team, wrong identifier:** `$O ping`. Expect a rejection like X7.
- [ ] **X9 client pins the helper:** `$F ping --expect-helper-id dev.farrier.wrong`. Expect **rejection**, because the
      client refuses a helper that doesn't match. Record the error.
- [ ] **X10 client outside the bundle:** `cp $F /tmp/fs-copy && /tmp/fs-copy ping`. It's the same signature, just a
      different location. (First VM run: **killed** on launch. The signature also covers the bundle.)
- [ ] **X10b symlink:** `ln -sf $F /tmp/farrier && /tmp/farrier info && /tmp/farrier ping`. This is how a Homebrew
      `farrier` command would work. Expect it to work, with `bundlePath` `/Applications/FarrierSpike.app`.

## 3. Console-session check

- [ ] **X11 local:** `$F whoami`. Expect `sessionOK: true`, `sessionHasGraphicAccess: true`,
      `sessionIsRemote: false`, and `consoleUser: juergen`. Record `sessionBits` and `sessionGetInfoStatus`.
- [ ] **X12 as root:** `sudo $F whoami`. Expect `sessionOK: false`, with the reason "caller euid 0 is not the console user".
- [ ] **X13 SSH:** turn on Remote Login and `ssh juergen@<VM-IP>`, then run
      `/Applications/FarrierSpike.app/Contents/MacOS/farrier-spike whoami`.
      Expect `sessionOK: false`, with `sessionIsRemote: true` and/or `sessionHasGraphicAccess: false`. **This is the
      key result for F4.** Record all the session fields. If `SessionGetInfo` failed (non-zero status), record
      that too. It would mean the method doesn't work for other processes' sessions, and we need another approach.
- [ ] **X14 Claude Code (optional):** have Claude Code in the VM run `$F whoami`. Expect `sessionOK: true`, because
      it runs in your console session.

## 4. Approval key and enrollment

- [ ] **X15 create key:** `$F key-create`. Expect no prompts.
- [ ] **X16 access list:** `$F key-acl`. Expect `integrityOK: true`, and `foreignTrustedApps` empty. Record the
      `entries`: which authorizations trust which paths.
- [ ] **X17 enroll:** `$F enroll`. Expect an **admin authorization dialog**. Record which program it names, its text,
      and whether it appeared in your session. Screenshot it. Enter admin credentials, then expect `ok: true` and a
      fingerprint that matches `localPublicKeyFingerprint`. Also record whether **loading** the key (to get its
      public key) caused a Touch ID or password prompt. It shouldn't.
- [ ] **X18 file:** `ls -l "/Library/Application Support/FarrierSpike/"`. Expect `approval-key.pub` owned by
      `root:wheel` with mode `-rw-r--r--`.
- [ ] **X19 cancel:** `$F enroll`, then click **Cancel** in the admin dialog. Expect `refused: admin authorization
      failed`, and record `authStatus` (expected -60006, errAuthorizationCanceled).
- [ ] **X20 SSH enroll:** over SSH, `.../farrier-spike enroll`. Expect a refusal by the session check
      **before** any dialog appears on the screen. Check the VM window: nothing should appear.
- [ ] **X21 authorization database:** `security authorizationdb read dev.farrier.spike.enroll-approval-key`. Expect
      a rule of `authenticate-admin`. Record it.

Re-enroll with `$F enroll` if X19 left it unenrolled.

## 5. Approval round trip

- [ ] **X22 approve:** `$F approve`. Expect the `begin` line `ok: true` with a nonce, then a password or Touch ID prompt with the
      text *"approve Farrier plan xxxxxxxx…: 3 items, 1.2 GB, irreversible"*, then `submit` with `ok: true, approved: true`.
- [ ] **X23 replay:** `$F approve --replay`. Expect `submit` ok, and `replay` refused ("unknown or already used nonce").
- [ ] **X24 tamper:** `$F approve --tamper`. Expect `submit` refused ("invalid signature").
- [ ] **X25 expiry:** `$F approve --delay 65`. Approve the prompt, wait. Expect `submit` refused ("approval expired").
      If launchd stopped the idle helper during the wait, the error is "unknown nonce" instead. Record which.
- [ ] **X26 SSH approve:** over SSH, `.../farrier-spike approve`. Expect `begin` refused by the session check, with no
      prompt in the VM window.
- [ ] **X27 attacker:** `$A approve`. Expect the XPC rejection, as in X7.

## 6. Access-list integrity check (F2)

- [ ] **X28 "Always Allow" (deliberately):** run
      `security find-generic-password -s dev.farrier.spike2.approval -a approval -w`. In the dialog, enter the
      password and click **Always Allow**. Then `$F key-acl`. Expect `integrityOK: false`, with `/usr/bin/security`
      in `foreignTrustedApps`. That shows the integrity check can detect it.
- [ ] Clean up X28: `$F key-delete && $F key-create && $F enroll`.

## 7. Updates

- [ ] **X29 app update:** the commit after the first VM run already changes the client (the key-acl fix), the helper
      (`helperPid` → `helperPID`) and the version (0.0.2 → 0.0.3). So `git pull`, rebuild, and reinstall with the same
      `ditto` command. Then:
  - [ ] `$F status`. Is it still `enabled`, or does it need registering or approving again?
  - [ ] `$F ping`. Does the **new** helper answer? Check that `helperPID` (the new key) appears, and the log
        shows a new "starting" line. If the old helper is still running, record that. Try
        `sudo launchctl kickstart -k system/dev.farrier.spike.helper` and record whether that's needed.
  - [ ] `$F approve`. Does the key still work, and is enrollment kept?

## 8. Clean up

```bash
$F reset
```

```bash
$F key-delete
```

```bash
$F unregister
```

```bash
sudo rm -rf /Applications/FarrierSpike.app "/Library/Application Support/FarrierSpike" /Library/Logs/farrier-spike-helper.log
```

```bash
sudo security authorizationdb remove dev.farrier.spike.enroll-approval-key
```

Turn Remote Login off again if you used it.
