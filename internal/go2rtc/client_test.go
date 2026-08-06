package go2rtc

import "testing"

func TestCredentialRedaction(t *testing.T) {
	in := `digraph { a [label="rtsp://user:secret@camera.local/live"] }`
	got := credentialURL.ReplaceAllString(in, `${1}***@`)
	want := `digraph { a [label="rtsp://***@camera.local/live"] }`
	if got != want {
		t.Fatalf("got %q", got)
	}
}
