(function () {
  "use strict";
  /* global vis */
  var ui = window.auditUI, loading = false, graphLoading = false, lastGraph = null, graphNetwork;
  function renderGraph(dot) {
    var data = vis.parseDOTNetwork(dot);
    var options = {edges: {font: {align: "middle"}, smooth: false}, nodes: {shape: "box"}, physics: false};
    if (!graphNetwork) {
      graphNetwork = new vis.Network(ui.byID("go2rtc-graph"), data, options); graphNetwork.storePositions();
    } else {
      var positions = graphNetwork.getPositions(), viewPosition = graphNetwork.getViewPosition(), scale = graphNetwork.getScale(), selectedNodes = graphNetwork.getSelectedNodes();
      graphNetwork.setData(data);
      Object.keys(positions).forEach(function (nodeID) { graphNetwork.moveNode(nodeID, positions[nodeID].x, positions[nodeID].y); });
      graphNetwork.moveTo({position: viewPosition, scale: scale}); graphNetwork.selectNodes(selectedNodes);
    }
    ui.byID("graph-state").textContent = data.nodes.length + " nodes, " + data.edges.length + " connections"; ui.byID("graph-state").className = "ok";
  }
  function render(data) {
    var fresh = ui.byID("fresh-state"); fresh.textContent = data.fresh ? "fresh" : "stale"; fresh.className = data.fresh ? "ok" : "bad";
    ui.byID("last-poll").textContent = data.last_poll; ui.byID("timezone").textContent = data.timezone; ui.byID("birdseye-source").textContent = data.birdseye_layout_source;
    var layout = ui.byID("birdseye-layout"); layout.replaceChildren();
    (data.birdseye_layout || []).forEach(function (camera) { var pill = document.createElement("span"); pill.className = "pill"; pill.textContent = camera; layout.appendChild(pill); });
    ui.renderRows("privacy-rows", data.privacy, 2, function (row, item) { ui.addCell(row, item.camera); ui.addCell(row, item.active ? "VIEWED" : "clear", item.active ? "bad" : "ok"); });
    ui.renderRows("session-rows", data.sessions, 9, function (row, item) {
      ui.addCell(row, item.last_seen_at); ui.addCell(row, item.started_at); ui.addCell(row, item.camera); ui.addCell(row, item.actor); ui.addCell(row, item.identity_confidence);
      ui.addCell(row, item.protocol); ui.addCell(row, item.remote_addr, "", true); ui.addCell(row, item.user_agent, "ua", true); ui.addExpected(row, item.expected);
    });
    ui.renderRows("activity-rows", data.activities, 3, function (row, item) { ui.addCell(row, item.actor); ui.addCell(row, item.remote_addr, "", true); ui.addCell(row, item.last_seen); });
    ui.byID("update-state").textContent = "updated automatically"; ui.byID("update-state").className = "";
  }
  async function refresh() {
    if (loading) { return; } loading = true;
    try { var response = await fetch("/audit/api/v1/live", {cache: "no-store"}); if (!response.ok) { throw new Error("HTTP " + response.status); } render(await response.json()); }
    catch (error) { ui.byID("update-state").textContent = "update failed; retrying"; ui.byID("update-state").className = "bad"; }
    finally { loading = false; }
  }
  async function refreshGraph() {
    if (graphLoading) { return; } graphLoading = true;
    try { var response = await fetch("/audit/api/v1/graph", {cache: "no-store"}); if (!response.ok) { throw new Error("HTTP " + response.status); } var dot = await response.text(); if (dot !== lastGraph) { renderGraph(dot); lastGraph = dot; } }
    catch (error) { ui.byID("graph-state").textContent = "Graph update failed; retrying"; ui.byID("graph-state").className = "bad"; }
    finally { graphLoading = false; }
  }
  function refreshVisible() { if (!document.hidden) { refresh(); refreshGraph(); } }
  refreshVisible(); setInterval(refreshVisible, 5000); document.addEventListener("visibilitychange", refreshVisible);
}());
