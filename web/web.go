// Package web embeds the static PWA assets (manifest and icon) served
// next to the dashboard.
package web

import _ "embed"

// Manifest is the web app manifest (served as /manifest.webmanifest).
//
//go:embed manifest.webmanifest
var Manifest []byte

// Icon512 is the 512×512 app icon (served as /icon-512.png).
//
//go:embed icon-512.png
var Icon512 []byte
