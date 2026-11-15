package audit

import (
	"strings"
	"testing"

	"github.com/user/evilpikin/internal/storage"
)

func TestGenerateFlagsTokenAndCreds(t *testing.T) {
	sessions := []*storage.CapturedSession{
		{
			ID:         "s1",
			TargetName: "Microsoft 365",
			Username:   "victim@corp.com",
			Password:   "hunter2",
			Cookies: map[string][]storage.CapturedCookie{
				"login.microsoftonline.com": {
					{Name: "ESTSAUTH", Value: "tok"},
				},
			},
			Status: "captured",
		},
	}
	out := Generate(sessions)
	for _, want := range []string{"CRITICAL", "ESTSAUTH", "FIDO2/WebAuthn", "AiTM"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q\n---\n%s", want, out)
		}
	}
}

func TestGenerateEmpty(t *testing.T) {
	out := Generate(nil)
	if !strings.Contains(out, "No captured sessions") {
		t.Fatalf("expected empty notice, got:\n%s", out)
	}
}
