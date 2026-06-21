# vmguard — fingerprint login on Linux for the Kensington VeriMark Guard

**The missing Linux driver/setup for the Kensington VeriMark™ Guard fingerprint
key.** `vmguard` lets you enroll your fingerprint and use it to log in on Linux —
graphical login, console login, `sudo`, and more — on a device that `fprintd`,
GNOME Settings, and most "fingerprint reader" tooling simply don't see.

Tested against the **VeriMark Guard 2.1 USB-C** key (`047d:813f`), but the
approach works for any of Kensington's FIDO2 match-on-chip VeriMark keys.

---

## Why you need this

If you plugged a VeriMark Guard into a Linux box and found that:

* GNOME/KDE settings show **no fingerprint reader**, and
* `fprintd-enroll` reports **no devices**, and
* nothing in `libfprint` supports it,

…that's expected. The VeriMark Guard is **not** a libfprint-style fingerprint
*reader*. Its USB HID report descriptor uses the FIDO usage page (`0xF1D0`):
it's a **FIDO2 / CTAP2 security key with match-on-chip biometrics**.

* The fingerprint sensor and templates live **inside the key**. Prints are
  enrolled and matched **on-chip** and **never reach the host**.
* The fingerprint is used as FIDO2 **user verification (UV)**.

So there is nothing for `fprintd`/libfprint to capture, and there never will be.
The supported path to "fingerprint login" on Linux is **FIDO2 + PAM**:

* **`vmguard`** (this project) manages the on-device PIN and fingerprints over
  CTAP2 — set PIN, enroll, list, delete.
* **`pam-u2f`** does the actual login gating: touching the key with an enrolled
  finger satisfies UV and logs you in.

This README walks you through the whole thing end to end.

---

## Features

* Enroll, list, rename, and delete fingerprints **on the key** from the CLI.
* Set and inspect the device PIN and retry counters.
* Inspect device capabilities and sensor characteristics.
* A safe, reversible `install-pam.sh` helper to wire fingerprint login into any
  PAM service (`sudo`, graphical login, TTY login, …) **without ever locking you
  out of password auth**.

## Requirements

* Linux with `systemd-logind` (so your user gets a seat ACL on the key's
  `hidraw` node — no root needed to talk to the key).
* A Rust toolchain (for building `vmguard`).
* Build deps for the `hidapi`/`ctap-hid-fido2` crates: `pkg-config` and
  `libudev-dev` (Debian/Ubuntu) or equivalent.
* `pam-u2f` for the login integration: `libpam-u2f` (Debian/Ubuntu), which also
  provides `pamu2fcfg`.

## Build

```sh
cargo build --release
# binary at: target/release/vmguard
```

Optionally put it on your `PATH`:

```sh
install -Dm755 target/release/vmguard ~/.local/bin/vmguard
```

Runtime access: your logged-in user already gets `rw` on the key's `/dev/hidrawN`
node via the systemd-logind seat ACL, so **no root is needed** to run `vmguard`.

## Commands

```sh
vmguard info                       # device capabilities + PIN/bio state (read-only)
vmguard bio-info                   # sensor type + samples needed per enrollment
vmguard set-pin                    # set the device PIN (prompted, hidden)
vmguard bio-enroll --name <name>   # enroll a finger (touch sensor ~7x)
vmguard bio-list                   # list enrolled fingerprints
vmguard bio-delete --id <hex>      # remove a fingerprint (id from bio-list)
vmguard wink                       # blink the key's LED (confirm you've got the right device)
vmguard reset                      # FACTORY RESET — wipe PIN + all fingerprints + credentials
```

PINs are prompted without echo. Pass `--pin <PIN>` to scripts only if you accept
it landing in shell history / the process list.

---

## Quick start — the setup wizard

The fastest path is the interactive wizard. Run it **as your normal user** (not
with `sudo` — it asks for `sudo` only when it needs to edit `/etc/pam.d`):

```sh
./install-pam.sh
```

It walks you through everything, detecting and skipping steps you've already done:

1. locating (or offering to build) the `vmguard` binary,
2. checking `pam_u2f` / `pamu2fcfg` are installed,
3. confirming the key is plugged in (and winking its LED),
4. setting a device PIN (if none is set),
5. enrolling a fingerprint (if none is enrolled),
6. registering the key's credential for PAM via `pamu2fcfg`,
7. handling an encrypted home (system-wide authfile), and
8. enabling the PAM services you pick — `sudo`, graphical login, TTY login, … —
   each with a timestamped backup.

To undo a service later:

```sh
./install-pam.sh --revert <service>     # e.g. gdm-password; omit to be prompted
```

If you'd rather do it by hand (or want to understand what the wizard does), the
manual steps are below.

## Step 1 — enroll a fingerprint and register the key

Do this once, before touching PAM.

1. **Set a PIN** (required before enrollment):
   ```sh
   vmguard set-pin
   ```
2. **Enroll a fingerprint** (touch the sensor ~7 times when prompted):
   ```sh
   vmguard bio-enroll --name right-index
   vmguard bio-list          # confirm it's there
   ```
3. **Register the key for PAM** with user-verification required (touch the
   enrolled finger when it blinks):
   ```sh
   mkdir -p ~/.config/Yubico
   pamu2fcfg -V > ~/.config/Yubico/u2f_keys
   # append more credentials with:  pamu2fcfg -V >> ~/.config/Yubico/u2f_keys
   ```

> `pamu2fcfg` uses Yubico's default `~/.config/Yubico/u2f_keys` path even though
> this isn't a YubiKey — that's just where `pam_u2f` looks by default.

## Step 2 — wire up PAM

`install-pam.sh` inserts this rule just before `@include common-auth` in the
chosen service, after backing the file up:

```
auth  sufficient  pam_u2f.so [authfile=/etc/u2f_mappings] userverification=1 cue [cue_prompt=Touch the VeriMark sensor]
```

* `sufficient` — a successful fingerprint logs you in; a missing/untouched/failed
  key falls through to your normal password. **You cannot lock yourself out.**
* `userverification=1` — forces biometric UV (the fingerprint).
* `[cue_prompt=…]` — the message shown while the key waits for a touch.

**Before you start**, keep a root shell open as a safety net, and — if your home
is **encrypted** — create a system-wide authfile (the graphical/console login
runs *before* your home is mounted, so it can't read
`~/.config/Yubico/u2f_keys`). The file holds only a credential id + public key
(not secret), so `644` root-owned is fine:

```sh
sudo -s                                                    # safety-net root shell; leave open
sudo cp ~/.config/Yubico/u2f_keys /etc/u2f_mappings        # only for gdm/login on encrypted home
sudo chmod 644 /etc/u2f_mappings
```

Then add the rule above to each service's file in `/etc/pam.d`, just before its
`@include common-auth` line (the wizard does exactly this, with a backup). Enable
`sudo` first and verify it before touching the login services. These are the
services worth enabling, what each unlocks, and how to test it:

| Unlocks | PAM service | Needs `authfile=`? | Verify |
|---|---|---|---|
| `sudo` / `sudo -s` | `sudo` | no | `sudo -k && sudo true` |
| `sudo -i` (login shell) | `sudo-i` | no | `sudo -k && sudo -i` |
| Graphical login | `gdm-password` | yes (encrypted home) | log out, log back in |
| Console login (TTY) | `login` | yes (encrypted home) | switch to a TTY (Ctrl+Alt+F3) |

Notes:

* `sudo -i` reads its **own** PAM service `sudo-i`, separate from `sudo` — enable
  both if you use `sudo -i`. `sudo -s` uses the plain `sudo` service.
* `authfile=/etc/u2f_mappings` is only needed for services that run before an
  encrypted home is mounted (`gdm-password`, `login`). `sudo`/`sudo-i` run after
  login, so they use the per-user `~/.config/Yubico/u2f_keys` and need no
  `authfile=`. Drop the `[authfile=…]` part of the rule for those.
* The PAM service file names above are Debian/Ubuntu conventions. Other distros
  may differ (e.g. `gdm-password` vs `gdm`); check your `/etc/pam.d`.
* **Revert any service** with `./install-pam.sh --revert <service>` (restores the
  newest timestamped backup the wizard made). Test each in a *fresh* session with
  the root shell still open.
* Re-run `sudo cp ~/.config/Yubico/u2f_keys /etc/u2f_mappings` whenever you
  add/remove credentials with `pamu2fcfg` — the system copy doesn't auto-update.

---

## Troubleshooting

* **`VeriMark Guard not found`** — confirm the key is plugged in and run
  `vmguard wink`; the LED should blink. If `vmguard info` works as root but not
  as your user, your session isn't getting the seat ACL — log in on a local seat
  (not over plain SSH) or add a udev rule granting your user `rw` on the device.
* **Touch never prompts at login** — make sure the matching `pam_u2f` line is in
  the right `/etc/pam.d/<service>` file and that the authfile actually contains a
  credential (`pamu2fcfg -V`). For encrypted homes, use `--authfile`.
* **Wrong-PIN lockout** — see Security notes below.

## Starting over — factory reset

To wipe the key completely — the PIN, every credential, and every enrolled
fingerprint — and return it to factory state:

```sh
vmguard reset
```

You'll be asked to type `RESET` to confirm (pass `--yes` to skip the prompt),
then to **touch the key**. Two caveats imposed by the authenticator itself:

* A reset is only accepted **shortly after the key is powered up** (typically
  within ~10 seconds of being plugged in), and *any* other command to the key
  (even `vmguard info`) consumes that window. If you get *"not allowed"* /
  *"operation denied"*, unplug the key, plug it back in, and run `vmguard reset`
  **first**, before anything else touches the key.
* This is the only way to recover a key that has **locked itself** after too many
  wrong-PIN attempts — but it erases your enrolled fingerprints in the process,
  so you'll re-run the wizard afterward.

## Security notes

* Wrong-PIN attempts decrement a retry counter; exhausting it **locks the key**
  (factory reset required, which wipes enrolled prints). `vmguard info` shows
  remaining PIN retries.
* `pam_u2f.so` here is `sufficient`, not `required`: it adds a passwordless
  fingerprint option without removing password auth. Use `required` (plus a
  password line) only if you deliberately want two-factor.
* Fingerprint templates never leave the key. `vmguard` only sends CTAP2 commands;
  it never sees raw biometric data.

## How it works (internals)

`vmguard` is a thin CLI over the [`ctap-hid-fido2`](https://crates.io/crates/ctap-hid-fido2)
crate. It speaks CTAP2 over CTAPHID directly to the key:

* `set-pin` → clientPIN `setPIN`
* `bio-enroll` / `bio-list` / `bio-delete` → `authenticatorBioEnrollment`
* `info` / `bio-info` → `authenticatorGetInfo` + bio sensor info
* `reset` → `authenticatorReset` (sent over a hand-rolled CTAPHID layer on
  `hidapi`, since `ctap-hid-fido2` doesn't expose reset)

Login is handled entirely by `pam_u2f`; `vmguard` is only the enrollment/management half.

## Contributing

Issues and PRs welcome — especially reports from **other VeriMark / FIDO2
match-on-chip keys** and **other distros**. If your key has a different
USB VID:PID, that's the value to change in `src/main.rs`.

## License

Released under the [MIT License](LICENSE).
