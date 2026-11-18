# Real case for 1.0: hardening sshd on a socket-activated Ubuntu server

Point 5 of the family's [stability bar](https://github.com/tui-tools/tui-kit/blob/main/docs/stability.md):
the tool has driven a real machine end to end for its main purpose, and what
that surfaced was fixed or filed.

## The machine, plainly

A lab virtual machine, not a production server: Ubuntu 24.04.5 LTS from the
stock cloud image, booted by [tui-lab](https://github.com/tui-tools/tui-lab)
under KVM on the project's own server, with OpenSSH 9.6p1 (Ubuntu
`1:9.6p1-3ubuntu13.20`), `ssh.socket` enabled and `ssh.service` disabled, as
Ubuntu ships it. The tool ran as the ordinary user `lab`, escalating with
`sudo -n`, in a terminal reached over SSH, which is how a server is driven.
The client was the host, logging in through the VM's forwarded SSH port. The
build was `main` at the time (2026-11-18) with the `R`/`x` split of this
release on top.

The same build also ran read-only on the project's own server, a Fedora 44
machine in daily use: `tui-ssh --check` exited 0 and read the effective
configuration from `sshd -T`, the unit, the host keys and the authentication
log. Nothing was changed on that machine.

## What was done, end to end

1. Opened on screen `1`: the header said `service: ssh running, via
   ssh.socket   config: effective   findings: 5`, so the socket-activated
   service was recognised and `sshd -T` was read.
2. `6`, then `A` for the account `ana`: the pasted `.pub` line was read back
   by `ssh-keygen` (`256 SHA256:eMMH…uI8 ana@laptop (ED25519)`) before the
   question, and written with `runuser -u ana -- install` and `tee`. A login
   as `ana` with that key from the host worked.
3. `e` three times, each through the drop-in
   `/etc/ssh/sshd_config.d/90-tui-ssh.conf`, each checked by `sshd -t -f`
   before the question and applied with `systemctl try-reload-or-restart ssh`:
   `X11Forwarding no` (findings 5 to 4), `MaxAuthTries 3` (4 to 3),
   `PermitRootLogin no`. `sshd -T` afterwards printed `x11forwarding no`,
   `maxauthtries 3`, `permitrootlogin no`.
4. `m`: `AllowTcpForwarding no` inside `Match User ana`, written below
   everything at file scope. `sshd -T -C user=ana,…` printed
   `allowtcpforwarding no` and the same for `lab` printed `yes`; from the host,
   `ssh -W localhost:22 ana@…` answered `stdio forwarding failed` while the
   same for `lab` returned the SSH banner.
5. `x` on `ana`'s key: the dialog said it was the last key and that, with
   `PasswordAuthentication no`, nothing else would get in. After `y`, a login
   with that key was refused (`Permission denied (publickey)`), and `R`
   re-read the server with `failed 24h: 3`.

## What it surfaced

- Before 1.0, `R` meant re-read on five screens and remove the selected key on
  the users screen. Fixed in this release: `x` removes a key and `R` re-reads
  everywhere, as in the rest of the family.
- A filter typed on one screen also filters the other five, although the help
  says "filter this screen": filed as
  [#36](https://github.com/tui-tools/tui-ssh/issues/36).
- The smoke test asserts socket activation on Ubuntu; it failed against the
  released 0.2.4, which predates #26, and passed with `main` on all three lab
  guests. It is in 1.0.0.

## What it did not cover

Host key regeneration (`K`), ending a session (`t`) and blocking an address
(`b`) were not exercised on this machine; they are covered by unit tests and
by the smoke test's reads only.

## Second run: tui-kit v0.5.0, on all three families

tui-kit v0.5.0 changed how a command runs as root: it is looked up only in the
system directories and must be owned by root, it starts from a minimal
environment, and as root the tool refuses configuration files root does not
own and `TUI_<TOOL>_*` variables carried in from sudo, su, doas or pkexec. So
the work above was repeated on 2026-11-18 with a static build of this branch's
head, `331e743` (main with tui-kit v0.5.0 and Go 1.27.4 merged in),
installed root-owned as `/usr/local/bin/tui-ssh`, on fresh tui-lab machines on
the project's own server: Ubuntu 24.04.5 (apt), Fedora 44 (dnf) and Omarchy
Server 4.0.1 (pacman), lab VMs again, not production hosts.

- The smoke test passed on all three as the ordinary user `lab`, who
  escalates with `sudo -n`, and again as root (`sudo env TUI_LAB_BIN=<binary> bash smoke.sh`):
  21/21 on each, as user and as root. On Omarchy Server the escalation and every command it runs were
  found through `/usr/sbin`, which the new kit trusts; nothing was refused.
- The main change was driven through the TUI in tmux once per family as
  `lab` and once as root, and checked on the machine afterwards:
  `MaxAuthTries` set through `e` and the drop-in, read back from `sshd -T`
  (4 as `lab`, 3 as root) on all three. On Omarchy, after the upgrade to
  OpenSSH 10.6, `--check` still read the effective configuration.
- tui-update then upgraded all three machines (see its report), Omarchy
  Server to 4.0.2. The smoke test passed again on the upgraded machines, and
  the new versions it observed are the 2026-11-18 lines in
  `compat/results.jsonl` (OpenSSH 10.6 on Omarchy Server 4.0.2).
- The contract change was driven on Ubuntu: with a key added for a test account
  through `A`, `R` on the users screen re-read without opening a removal and
  the key stayed; `x` opened the removal and, after `y`, the file was empty.

No new finding.
