package auditweb

import _ "embed"

//go:embed overview.html
var overviewHTML string

//go:embed history.html
var historyHTML string

//go:embed audit.css
var auditCSS string

//go:embed common.js
var commonJS string

//go:embed overview.js
var overviewJS string

//go:embed history.js
var historyJS string
