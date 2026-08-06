(function () {
  "use strict";
  var ui = window.auditUI, loading = false;
  function render(data) {
    ui.byID("timezone").textContent = data.timezone;
    ui.renderRows("event-rows", data.events, 7, function (row, item) {
      ui.addCell(row, item.last_seen_at); ui.addCell(row, item.started_at); ui.addCell(row, item.kind); ui.addCell(row, item.camera); ui.addCell(row, item.actor); ui.addCell(row, item.details, "", true); ui.addExpected(row, item.expected);
    });
    ui.renderRows("recording-rows", data.recordings, 7, function (row, item) {
      ui.addCell(row, item.last_seen_at); ui.addCell(row, item.started_at); ui.addCell(row, item.kind); ui.addCell(row, item.camera); ui.addCell(row, item.actor); ui.addCell(row, item.protocol); ui.addCell(row, item.details, "", true);
    });
    ui.renderRows("stream-rows", data.stream_events, 7, function (row, item) {
      ui.addCell(row, item.live ? "live" : item.last_seen_at, item.live ? "ok" : ""); ui.addCell(row, item.started_at); ui.addCell(row, item.camera); ui.addCell(row, item.actor); ui.addCell(row, item.protocol); ui.addCell(row, item.user_agent, "ua", true); ui.addExpected(row, item.expected);
    });
    ui.byID("update-state").textContent = "updated " + new Date().toLocaleTimeString(); ui.byID("update-state").className = "";
  }
  async function refresh() {
    if (loading) { return; } loading = true; ui.byID("refresh-button").disabled = true;
    try { var response = await fetch("/audit/api/v1/history/dashboard", {cache: "no-store"}); if (!response.ok) { throw new Error("HTTP " + response.status); } render(await response.json()); }
    catch (error) { ui.byID("update-state").textContent = "update failed"; ui.byID("update-state").className = "bad"; }
    finally { loading = false; ui.byID("refresh-button").disabled = false; }
  }
  ui.byID("refresh-button").addEventListener("click", refresh);
  function refreshVisible() { if (!document.hidden) { refresh(); } }
  refreshVisible(); setInterval(refreshVisible, 30000); document.addEventListener("visibilitychange", refreshVisible);
}());
