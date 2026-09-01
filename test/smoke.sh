#!/bin/bash
# Backend smoke test for tui-ssh, run inside a lab guest.
#
# The contract (see tui-tools/tui-lab): this script runs on the guest as the
# unprivileged lab user, escalates with `sudo -n` only, prints a short PASS/FAIL
# table and exits non-zero if anything failed. The binary under test is at
# $TUI_LAB_BIN (default: tui-ssh on PATH).
#
# What it proves is that the tool reads the machine's *real* SSH server and
# agrees with the machine's own tooling — not that a fake renders. The lab
# already covers --version and a --demo frame; this covers the backend.
#
# Everything here is read-only. The tool is never asked to write its drop-in,
# reload the service, end a session or replace a host key: a suite that changed
# the SSH configuration of the machine it runs on would be a suite nobody could
# run twice, and on a guest reached over SSH it would be a suite that cut its
# own connection.
#
# Two shapes of machine are asserted, because both are normal:
#
#   privileged     `sudo -n` works, so `sshd -T` answers and the settings the
#                  tool shows are sshd's own.
#   unprivileged   `sudo -n` refuses, so the configuration is read from the
#                  files instead and the tool must say so rather than show an
#                  empty screen.
set -uo pipefail

bin="${TUI_LAB_BIN:-tui-ssh}"
# TOOL is the manifest name, which is what a compatibility result is keyed on.
TOOL=tui-ssh
pass=0
fail=0

# check runs one assertion. It takes a label, a command and a grep pattern the
# command's output must match. Output is captured so a failure can show it.
check() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# check_absent is the inverse of a grep assertion: the command must succeed and
# its output must NOT contain the pattern. It is what proves a read stayed a
# read, which is a claim about something that did not happen.
check_absent() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && ! grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# --- compatibility evidence -------------------------------------------------
#
# The manifest's `tested` list is generated, not claimed: it is rebuilt from
# compat/results.jsonl by tui-kit/tools/compat-sync.py, and this is where a
# line of that file comes from. The version recorded is the one the tool itself
# probed, read back out of --check, so it describes the machine that really ran
# the suite rather than what the tester assumed was installed.
#
# The line is printed behind a `compat-result:` prefix so it survives the trip
# out of the guest through the lab's per-VM log, and appended to
# $TUI_COMPAT_RESULTS as well for a run outside the lab.
record_compat() {
  local report="$1" outcome="$2" backend version distro today block
  block=$(sed -n '/"compat": {/,/^  }/p' <<<"$report")
  backend=$(sed -n 's/.*"backend": "\([^"]*\)".*/\1/p' <<<"$block" | head -1)
  version=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' <<<"$block" | head -1)
  if [[ -z $backend || -z $version ]]; then
    echo "      no version was probed, so no compatibility result is recorded"
    return
  fi

  distro=$(. /etc/os-release && echo "${ID}-${VERSION_ID:-rolling}")
  today=$(date -u +%Y-%m-%d)
  local line
  line=$(printf '{"backend":"%s","date":"%s","distro":"%s","result":"%s","suite":"smoke","tool":"%s","version":"%s"}' \
    "$backend" "$today" "$distro" "$outcome" "$TOOL" "$version")

  printf 'compat-result: %s\n' "$line"
  if [[ -n ${TUI_COMPAT_RESULTS:-} ]]; then
    printf '%s\n' "$line" >>"$TUI_COMPAT_RESULTS"
  fi
}

echo "--- tui-ssh smoke on $(. /etc/os-release && echo "$PRETTY_NAME")"

if ! command -v sshd >/dev/null && [[ ! -x /usr/sbin/sshd ]]; then
  echo "FAIL  no SSH server is installed on this machine"
  exit 1
fi

# Which unit this machine calls the server, decided the way the tool decides it.
if systemctl show sshd --property=LoadState 2>/dev/null | grep -q '=loaded'; then
  unit=sshd
elif systemctl show ssh --property=LoadState 2>/dev/null | grep -q '=loaded'; then
  unit=ssh
else
  unit=none
fi
echo "      unit=$unit"

# Whether the machine will let this user run `sshd -T`, which decides whether
# the settings come from sshd or from the files.
if sudo -n true 2>/dev/null; then
  privileged=yes
else
  privileged=no
fi
echo "      sudo -n=$privileged"

# --- the report block ------------------------------------------------------
#
# --report is read-only and unprivileged, so it is smoked without sudo: a user
# who cannot escalate is exactly the one who most needs to be able to file a
# usable bug. What is asserted is that it names the backend this machine
# drives, that it still answers under --demo, and that it keeps its privacy
# promise — the block goes into a public issue, so a home path or the host name
# appearing in it is a bug, not a cosmetic detail.
check "report names the selected backend" \
  "$bin --report" \
  '^backend: openssh'

check "report says the run was live" \
  "$bin --report" \
  '^mode: live$'

check "report works in demo mode too" \
  "$bin --demo --report" \
  '^backend: demo$'

check "and says so on the mode line" \
  "$bin --demo --report" \
  '^mode: demo'

# The distro and kernel lines are excluded from the host-name search rather
# than from the promise: they are built from /etc/os-release and from uname's
# release and machine fields, never from its nodename, and on a guest called
# "fedora" or "ubuntu" — which is most of them — the host name is a substring
# of the distribution's own. Everything else in the block is searched.
check "report leaks neither a home path nor the host name" \
  "$bin --report | grep -vE '^(distro|kernel): ' | grep -cE '/home/|$(uname -n)' || true" \
  '^0$'

# 1. The read path works at all and names the backend it drove.
check "check reads the server" \
  "$bin --check" \
  '"backend": "openssh"'

# 2. The unit name matches what systemd calls it. This is the assertion that
#    catches the Debian/Ubuntu `ssh` versus Fedora/Arch `sshd` split: a tool
#    that guessed would build `systemctl reload sshd` on a machine where that
#    unit is only an alias, or does not exist at all.
if [[ $unit != none ]]; then
  check "the unit is reported as $unit" \
    "$bin --check" \
    "\"unit\": \"$unit\""

  active=$(systemctl is-active "$unit" 2>/dev/null)
  if [[ $active == active ]]; then
    check "the service is reported as running" "$bin --check" '"active": true'
  fi
fi

# 3. The security-relevant settings came back with a verdict each — when the
#    configuration could be read at all. Whether it could is a property of the
#    machine, not of the tool: Fedora and Arch ship sshd_config mode 0600, so a
#    plain user with no `sudo -n` can read neither `sshd -T` nor the file, and
#    the honest answer there is an empty list plus a reason (asserted below).
if [[ $privileged == yes ]] || [[ -r /etc/ssh/sshd_config ]]; then
  check "the security settings were judged" \
    "$bin --check" \
    '"key": "PermitRootLogin"'

  check "every judged setting carries a verdict" \
    "$bin --check" \
    '"verdict": "(ok|warn|risk)"'
else
  echo "SKIP  sshd_config is not readable by this user and sudo -n refuses"
fi

# 4. The host keys were read. `ssh-keygen -lf` on a *public* key needs no
#    privileges, so this must work as the plain lab user.
keys=$(ls /etc/ssh/ssh_host_*_key.pub 2>/dev/null | wc -l)
if [[ $keys -gt 0 ]]; then
  check "the $keys host keys are fingerprinted" \
    "$bin --check" \
    '"fingerprint": "SHA256:'
fi

# 5. The sessions read works. There is at least one — the lab reaches the guest
#    over SSH — but a guest driven through a serial console has none, so the
#    assertion is on the field existing rather than on a count.
check "the sessions were read" "$bin --check" '"sessions": [0-9]+'

# 6. The authentication log was read over the day. A machine that has just
#    booted may have no failures at all, so again the field, not a count.
check "the auth log was read" "$bin --check" '"failedLogins": [0-9]+'

# 6b. The local accounts were read from /etc/passwd, which is world-readable
#     everywhere, so this holds for the plain lab user too. The keys on them
#     are another matter: another account's ~/.ssh is mode 700, so the count
#     is asserted as a field rather than as a number.
check "the local accounts were read" "$bin --check" '"accounts": [1-9][0-9]*'
check "the authorized keys were counted" "$bin --check" '"authorizedKeys": [0-9]+'

# 6c. The read path never writes. `--check` builds no mutation at all, and the
#     one file this tool would rewrite under a home directory must be exactly
#     as it was before and after.
before=$(sha256sum ~/.ssh/authorized_keys 2>/dev/null || echo none)
$bin --check >/dev/null 2>&1 || true
after=$(sha256sum ~/.ssh/authorized_keys 2>/dev/null || echo none)
if [[ $before == "$after" ]]; then
  printf 'PASS  --check left ~/.ssh/authorized_keys untouched\n'
  pass=$((pass + 1))
else
  printf 'FAIL  --check changed ~/.ssh/authorized_keys\n'
  fail=$((fail + 1))
fi

case "$privileged" in
  yes)
    # 7. With `sudo -n`, `sshd -T` answers and the settings are sshd's own.
    #    This is the case a hardened server is in, and the one where the
    #    verdicts are worth trusting.
    check "the configuration is the effective one" \
      "$bin --check" \
      '"effective": true'

    # And it agrees with sshd itself, asked directly.
    #
    # The keyword is matched case-insensitively because sshd changed how it
    # prints one. Through OpenSSH 10.2 `sshd -T` lower-cases every keyword
    # (`permitrootlogin no`); 10.5 prints the canonical spelling instead
    # (`PermitRootLogin no`). A lowercase-only match here found nothing on
    # Omarchy Server 4.0.1 and quietly skipped the strongest assertion in this
    # file, on the one machine in the lab that keeps root out entirely.
    want=$(sudo -n sshd -T 2>/dev/null |
      sed -n 's/^[Pp]ermit[Rr]oot[Ll]ogin //p' | head -1)
    if [[ -n $want ]]; then
      check "PermitRootLogin matches \`sshd -T\` ($want)" \
        "$bin --check" \
        "\"value\": \"$want\""
    else
      printf 'FAIL  sshd -T printed no PermitRootLogin line to compare against\n'
      fail=$((fail + 1))
    fi
    ;;

  no)
    # 7. Without it the files are read instead. The tool must still produce
    #    settings — this is the case that would otherwise show an empty screen
    #    on Fedora and Arch, where sshd_config is mode 0600 — and it must say
    #    that what it is showing is the files rather than sshd's answer.
    check "the fallback says it is reading the files" \
      "$bin --check" \
      '"effective": false'

    check "a reason is given for the fallback" \
      "$bin --check" \
      '"effectiveReason": ".+"'
    ;;
esac

# 8. --check must never change anything. The drop-in this tool writes must not
#    exist because of a read, and the service must be in the state it was.
before_dropin=$(sudo -n test -e /etc/ssh/sshd_config.d/90-tui-ssh.conf 2>/dev/null && echo present || echo absent)
before_state=$(systemctl show "$unit" --property=ActiveEnterTimestamp 2>/dev/null)
$bin --check >/dev/null 2>&1
after_dropin=$(sudo -n test -e /etc/ssh/sshd_config.d/90-tui-ssh.conf 2>/dev/null && echo present || echo absent)
after_state=$(systemctl show "$unit" --property=ActiveEnterTimestamp 2>/dev/null)
if [[ "$before_dropin" == "$after_dropin" && "$before_state" == "$after_state" ]]; then
  printf 'PASS  --check left the server untouched\n'
  pass=$((pass + 1))
else
  printf 'FAIL  --check changed the server (%s→%s, %s→%s)\n' \
    "$before_dropin" "$after_dropin" "$before_state" "$after_state"
  fail=$((fail + 1))
fi

# 9. And it prints no mutation: --check reports the read path, and a command
#    line in its output would mean it had built one.
check_absent "--check builds no command" \
  "$bin --check" \
  'systemctl reload|install -m 600|loginctl terminate-session|ssh-keygen -A'

if [[ $fail -eq 0 ]]; then
  record_compat "$("$bin" --check 2>/dev/null)" pass
else
  record_compat "$("$bin" --check 2>/dev/null)" fail
fi

echo "--- tui-ssh: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
