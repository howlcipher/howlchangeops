package main

import (
	"strings"
	"testing"
)

func TestParseApproveFlags(t *testing.T) {
	f := parseApproveFlags([]string{"--owner-confirmed", "--approver", "alice"})
	if !f.ownerConfirmed || f.approver != "alice" {
		t.Fatalf("got %+v", f)
	}
	if f := parseApproveFlags([]string{"--approver=bob"}); f.ownerConfirmed || f.approver != "bob" {
		t.Fatalf("got %+v", f)
	}
}

func TestApproverDefaultsToTheOSUserNeverAdmin(t *testing.T) {
	if got := approverName("  carol "); got != "carol" {
		t.Fatalf("named approver = %q", got)
	}
	if got := approverName(""); got == "" || got == "admin" {
		t.Fatalf("default approver = %q", got)
	}
}

func TestOnlyYesConfirms(t *testing.T) {
	for answer, want := range map[string]bool{"y\n": true, "YES\n": true, "\n": false, "n\n": false, "": false, "yes please\n": false} {
		if got := confirmAtTerminal(strings.NewReader(answer)); got != want {
			t.Errorf("confirmAtTerminal(%q) = %v, want %v", answer, got, want)
		}
	}
}

func TestConfirmationIsSigned(t *testing.T) {
	key := []byte("secret_key_32_bytes_long_fixture")
	a := Approval{Schema: "howlchangeops.approval/v1", DecisionID: "d", Approver: "alice", Confirmation: "terminal"}
	b := a
	b.Confirmation = "owner_relayed"
	if signApproval(a, key) == signApproval(b, key) {
		t.Fatal("changing how an approval was confirmed must invalidate its signature")
	}
}

func TestAuthorizationGuaranteeIsSigned(t *testing.T) {
	key := []byte("synthetic-fixture-key")
	a := Approval{AuthorizationGuarantee: "cooperative_confirmation_only", DecisionID: "synthetic"}
	b := a
	b.AuthorizationGuarantee = "independently_authenticated"
	if signApproval(a, key) == signApproval(b, key) {
		t.Fatal("changing authorization guarantee must invalidate signature")
	}
	b.AuthorizationGuarantee = ""
	if signApproval(a, key) == signApproval(b, key) {
		t.Fatal("removing authorization guarantee must invalidate signature")
	}
}
