package web

import "embed"

// staticAssets are compile-time fixed and never depend on the process working
// directory, filesystem traversal, symlinks, or external assets.
//
//go:embed static/index.html static/app.js static/styles.css
var staticAssets embed.FS
