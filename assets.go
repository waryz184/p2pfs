package p2pfs

import "embed"

// WebFS embarque toute la WebUI (HTML/JS/CSS + bundle crypto) dans le binaire.
//
//go:embed all:web
var WebFS embed.FS
