package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/openssh"
	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// TestRootLoginAliasPreselectsProhibitPassword is the regression test for the
// editor starting on "no" when sshd -T reports PermitRootLogin as
// "without-password", the deprecated spelling of "prohibit-password" that
// OpenSSH 9.6 on Ubuntu 24.04 still prints for the default.
func TestRootLoginAliasPreselectsProhibitPassword(t *testing.T) {
	caps := openssh.Capabilities()
	for reported, want := range map[string]string{
		"without-password":     "prohibit-password",
		"Without-Password":     "prohibit-password",
		"prohibit-password":    "prohibit-password",
		"forced-commands-only": "forced-commands-only",
		"yes":                  "yes",
		"no":                   "no",
	} {
		model := ssh.Model{Settings: []ssh.Setting{{Key: "PermitRootLogin", Value: reported}}}
		form := newSettingForm("PermitRootLogin", model, caps)
		if got := form.value(); got != want {
			t.Errorf("reported %q: the editor starts on %q, want %q", reported, got, want)
		}
		if form.current != reported {
			t.Errorf("reported %q: the form shows %q as the current value", reported, form.current)
		}
	}
}

// TestServiceScreenShowsSocketActivation: on Ubuntu 24.04 ssh.service is
// disabled by design and ssh.socket is what is enabled; the screen has to say
// so, and an idle service behind a listening socket is not a stopped server.
func TestServiceScreenShowsSocketActivation(t *testing.T) {
	a, _ := newTestApp(t)
	a.model.Service = ssh.Service{Unit: "ssh", ActiveState: "inactive",
		UnitFileState: "disabled", Socket: "ssh.socket", SocketActiveState: "active",
		SocketUnitFileState: "enabled", SocketActivated: true}

	rows := map[string]string{}
	for _, row := range a.serviceRows() {
		rows[row.label] = row.value
	}
	if rows["enabled"] != "disabled (ssh.socket starts it)" {
		t.Errorf("enabled row = %q", rows["enabled"])
	}
	if rows["socket"] != "socket-activated: ssh.socket enabled, active" {
		t.Errorf("socket row = %q", rows["socket"])
	}
	if header := a.headerView(); !strings.Contains(header, "ssh idle, ssh.socket listening") {
		t.Errorf("header does not say the socket is listening:\n%s", header)
	}

	// A plain sshd.service host keeps its rows exactly.
	a.model.Service = ssh.Service{Unit: "sshd", Active: true, ActiveState: "active",
		UnitFileState: "enabled"}
	for _, row := range a.serviceRows() {
		if row.label == "socket" || strings.Contains(row.value, "socket") {
			t.Errorf("sshd host grew a socket row: %+v", row)
		}
	}
}
