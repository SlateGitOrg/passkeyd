// Package web embeds the static demo page served at "/": plain HTML, CSS
// and JavaScript with no framework and no build step.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var static embed.FS

// FS is the static site rooted at the page directory.
var FS = mustSub(static, "static")

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err) // the directory is embedded at compile time
	}
	return sub
}
