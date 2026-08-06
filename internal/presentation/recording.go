package presentation

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// RecordingDetails replaces Frigate's Unix start/end values with a compact,
// minute-level local range. Unrecognized details are returned unchanged.
func RecordingDetails(details string, location *time.Location) string {
	rangeDetails, exportName := splitExportName(details)
	fields := strings.Fields(rangeDetails)
	startIndex, endIndex := -1, -1
	var start, end time.Time
	for index, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "start":
			parsed, valid := unixSeconds(value)
			if valid {
				startIndex, start = index, parsed
			}
		case "end":
			parsed, valid := unixSeconds(value)
			if valid {
				endIndex, end = index, parsed
			}
		}
	}
	if startIndex < 0 || endIndex < 0 {
		return details
	}
	if location == nil {
		location = time.UTC
	}
	rangeField := "range=" + compactRange(start.In(location), end.In(location))
	out := make([]string, 0, len(fields)-1)
	for index, field := range fields {
		switch index {
		case startIndex:
			out = append(out, rangeField)
		case endIndex:
			// The end value is included in the range field.
		default:
			out = append(out, field)
		}
	}
	formatted := strings.Join(out, " ")
	if exportName != "" {
		formatted += " export_name=" + exportName
	}
	return formatted
}

func splitExportName(details string) (string, string) {
	const marker = " export_name="
	if index := strings.Index(details, marker); index >= 0 {
		return details[:index], details[index+len(marker):]
	}
	return details, ""
}

func unixSeconds(value string) (time.Time, bool) {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return time.Time{}, false
	}
	whole, fraction := math.Modf(seconds)
	return time.Unix(int64(whole), int64(math.Round(fraction*1e9))).UTC(), true
}

func compactRange(start, end time.Time) string {
	_, startOffset := start.Zone()
	_, endOffset := end.Zone()
	if startOffset != endOffset {
		return start.Format("2006-01-02 15:04 -07") + "–" + end.Format("2006-01-02 15:04 -07")
	}
	if start.Year() == end.Year() && start.YearDay() == end.YearDay() {
		return start.Format("2006-01-02 15:04") + "–" + end.Format("15:04 -07")
	}
	return start.Format("2006-01-02 15:04") + "–" + end.Format("2006-01-02 15:04 -07")
}
