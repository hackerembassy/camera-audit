package mqttpub

import "testing"

func TestSlug(t *testing.T) {
	if got := slug("Electronics Room / Main"); got != "electronics_room_main" {
		t.Fatalf("unexpected slug %q", got)
	}
}
