package webapp

// These are intended to be set via -ldflags at build time.
// Keep defaults stable for local dev.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

