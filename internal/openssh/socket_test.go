package openssh

import (
	"reflect"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// ubuntuSocketService is ssh.service and ssh.socket as Ubuntu 24.04 reports
// them (fixtures from `systemctl show`): the service disabled, the socket
// enabled and listening.
func ubuntuSocketService(t *testing.T) ssh.Service {
	t.Helper()
	unit := ParseProperties(fixture(t, "systemctl-show-ssh-ubuntu2404.txt"))
	service := ssh.Service{Unit: "ssh", ActiveState: unit["ActiveState"],
		UnitFileState: unit["UnitFileState"], Active: unit["ActiveState"] == "active"}
	socket := SocketUnitFor(unit["Id"], service.Unit)
	ApplySocketProperties(&service, socket,
		ParseProperties(fixture(t, "systemctl-show-ssh-socket-ubuntu2404.txt")))
	return service
}

func TestSocketActivationIsDetected(t *testing.T) {
	service := ubuntuSocketService(t)
	if service.UnitFileState != "disabled" {
		t.Fatalf("fixture: ssh.service is %q, want disabled", service.UnitFileState)
	}
	if !service.SocketActivated || service.Socket != "ssh.socket" ||
		service.SocketUnitFileState != "enabled" || service.SocketActiveState != "active" {
		t.Errorf("service = %+v, want socket-activated by an enabled, active ssh.socket", service)
	}
}

func TestSocketUnitFor(t *testing.T) {
	for _, c := range []struct{ id, unit, want string }{
		{"ssh.service", "sshd", "ssh.socket"}, // found through the sshd.service alias
		{"ssh.service", "ssh", "ssh.socket"},
		{"sshd.service", "sshd", "sshd.socket"},
		{"", "sshd", "sshd.socket"},
	} {
		if got := SocketUnitFor(c.id, c.unit); got != c.want {
			t.Errorf("SocketUnitFor(%q, %q) = %q, want %q", c.id, c.unit, got, c.want)
		}
	}
}

// TestAnIdleSocketLeavesTheServiceAlone is the Fedora case: sshd.socket ships
// disabled and inactive, sshd.service runs sshd, and nothing changes.
func TestAnIdleSocketLeavesTheServiceAlone(t *testing.T) {
	for _, properties := range []map[string]string{
		{"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"},
		{"LoadState": "not-found", "ActiveState": "inactive"},
		{},
	} {
		service := ssh.Service{Unit: "sshd", Active: true, Enabled: true,
			ActiveState: "active", UnitFileState: "enabled"}
		before := service
		ApplySocketProperties(&service, "sshd.socket", properties)
		if !reflect.DeepEqual(service, before) {
			t.Errorf("%v changed the service: %+v", properties, service)
		}
		reload, err := BuildServiceReload(service)
		if err != nil || reload.String() != "systemctl reload sshd" {
			t.Errorf("reload = %q, %v; want systemctl reload sshd", reload.String(), err)
		}
	}
}

// TestSocketActivatedReloadWorksWhenIdle: `systemctl reload ssh` fails while
// ssh.service waits for its first connection ("ssh.service is not active,
// cannot reload"), so a socket-activated machine gets try-reload-or-restart.
func TestSocketActivatedReloadWorksWhenIdle(t *testing.T) {
	service := ubuntuSocketService(t)
	reload, err := BuildServiceReload(service)
	if err != nil {
		t.Fatal(err)
	}
	if got := reload.String(); got != "systemctl try-reload-or-restart ssh" {
		t.Errorf("reload = %q", got)
	}

	apply, err := BuildApplyDropIn(service, "PasswordAuthentication")
	if err != nil || len(apply) != 1 || apply[0].String() != reload.String() {
		t.Errorf("apply = %v, %v", apply, err)
	}

	// A listening change moves the socket, which only a regenerate and a
	// restart of ssh.socket do.
	for _, key := range []string{"Port", "listenaddress"} {
		apply, err = BuildApplyDropIn(service, key)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, cmd := range apply {
			got = append(got, cmd.String())
		}
		want := []string{"systemctl daemon-reload", "systemctl restart ssh.socket"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: apply = %q, want %q", key, got, want)
		}
	}

	// The host key regeneration ends with the same reload.
	commands, err := BuildRegenerateHostKeys(
		[]ssh.HostKey{{Path: "/etc/ssh/ssh_host_ed25519_key.pub"}}, service, "20261023-120000")
	if err != nil {
		t.Fatal(err)
	}
	if last := commands[len(commands)-1].String(); last != reload.String() {
		t.Errorf("regeneration ends with %q", last)
	}

	// And without socket activation every change is still a plain reload.
	plain := ssh.Service{Unit: "sshd"}
	apply, err = BuildApplyDropIn(plain, "Port")
	if err != nil || len(apply) != 1 || apply[0].String() != "systemctl reload sshd" {
		t.Errorf("sshd host: apply = %v, %v", apply, err)
	}
}
