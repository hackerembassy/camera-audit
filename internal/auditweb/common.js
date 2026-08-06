(function () {
  "use strict";
  function byID(id) { return document.getElementById(id); }
  function addCell(row, value, className, code) {
    var cell = document.createElement("td");
    var content = code ? document.createElement("code") : document.createElement("span");
    content.textContent = value || "—";
    if (className) { cell.className = className; }
    cell.appendChild(content); row.appendChild(cell);
  }
  function addExpected(row, expected) {
    var cell = document.createElement("td");
    var label = document.createElement("strong");
    label.textContent = expected ? "yes" : "no";
    label.className = expected ? "ok" : "bad";
    cell.appendChild(label); row.appendChild(cell);
  }
  function renderRows(id, items, columns, render) {
    var body = byID(id); body.replaceChildren();
    if (!items || items.length === 0) {
      var empty = document.createElement("tr");
      var cell = document.createElement("td");
      cell.colSpan = columns; cell.className = "muted"; cell.textContent = "None observed";
      empty.appendChild(cell); body.appendChild(empty); return;
    }
    items.forEach(function (item) {
      var row = document.createElement("tr"); render(row, item); body.appendChild(row);
    });
  }
  window.auditUI = {byID: byID, addCell: addCell, addExpected: addExpected, renderRows: renderRows};
}());
