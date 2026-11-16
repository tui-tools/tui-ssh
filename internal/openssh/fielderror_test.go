package openssh

import (
	"errors"
	"strings"
	"testing"

	"github.com/tui-tools/tui-ssh/internal/ssh"
)

// TestValidationNamesTheFieldAndNeverTheValue: every refusal of a typed value
// says which form field it is about and what would be accepted, and none of
// them quotes the value back.
func TestValidationNamesTheFieldAndNeverTheValue(t *testing.T) {
	const secret = "Zq9SecretPaste"
	cases := []struct {
		name  string
		err   error
		field string
		says  string
	}{
		{"pattern", CheckValue("MaxAuthTries", secret), ssh.FieldValue,
			"whole number"},
		{"comment", CheckValue("AllowUsers", "ana #"+secret), ssh.FieldValue,
			"newline or a #"},
		{"choice", CheckValue("PermitRootLogin", secret), ssh.FieldValue,
			"must be one of"},
		{"listen", CheckValue("ListenAddress", secret), ssh.FieldValue,
			"IPv4 or IPv6"},
		{"not editable", CheckValue("Banner", secret), ssh.FieldKey,
			"does not edit"},
		{"match type", matchErr("Host"+secret, "x"), ssh.FieldMatchType,
			"selects on"},
		{"match address", matchErr(MatchAddress, "10.0.0.0/8,"+secret),
			ssh.FieldMatchValue, "item 2"},
		{"match user", matchErr("User", secret+"/"), ssh.FieldMatchValue,
			"user pattern"},
	}
	for _, tc := range cases {
		var refused *ssh.FieldError
		if !errors.As(tc.err, &refused) {
			t.Errorf("%s: %v is not a FieldError", tc.name, tc.err)
			continue
		}
		if refused.Field != tc.field {
			t.Errorf("%s: field %q, want %q", tc.name, refused.Field, tc.field)
		}
		if !strings.Contains(refused.Reason, tc.says) {
			t.Errorf("%s: reason %q does not say %q", tc.name, refused.Reason, tc.says)
		}
		if strings.Contains(tc.err.Error(), "SecretPaste") {
			t.Errorf("%s: the refusal echoes the value: %q", tc.name, tc.err)
		}
	}
}

// matchErr is the error MatchCriteria returns.
func matchErr(matchType, value string) error {
	_, err := MatchCriteria(matchType, value)
	return err
}
