package presentation

import (
	"fmt"
	"testing"
	"time"
)

func TestRecordingDetailsFormatsCompactLocalRange(t *testing.T) {
	location, err := time.LoadLocation("Asia/Yerevan")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 8, 6, 7, 30, 45, 123000000, time.UTC)
	end := time.Date(2026, 8, 6, 7, 45, 59, 0, time.UTC)
	details := "mode=batch item=1/2 start=" + unixString(start) + " end=" + unixString(end)
	if got, want := RecordingDetails(details, location), "mode=batch item=1/2 range=2026-08-06 11:30–11:45 +04"; got != want {
		t.Fatalf("RecordingDetails()=%q, want %q", got, want)
	}
}

func TestRecordingDetailsShowsBothDatesAcrossMidnight(t *testing.T) {
	location, err := time.LoadLocation("Asia/Yerevan")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 8, 6, 19, 55, 0, 0, time.UTC)
	end := start.Add(10 * time.Minute)
	details := "start=" + unixString(start) + " end=" + unixString(end)
	if got, want := RecordingDetails(details, location), "range=2026-08-06 23:55–2026-08-07 00:05 +04"; got != want {
		t.Fatalf("RecordingDetails()=%q, want %q", got, want)
	}
}

func TestRecordingDetailsPreservesUnknownMetadata(t *testing.T) {
	for _, details := range []string{"event=abc", "start=invalid end=123", "start=123"} {
		if got := RecordingDetails(details, time.UTC); got != details {
			t.Fatalf("RecordingDetails(%q)=%q", details, got)
		}
	}
}

func unixString(value time.Time) string {
	return fmt.Sprintf("%d.%09d", value.Unix(), value.Nanosecond())
}
