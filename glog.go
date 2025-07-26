package log

import (
	"context"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"log/slog"
)

// GlogHandler wraps a slog.Handler to provide glog-style verbosity and vmodule filtering.
type GlogHandler struct {
	handler     slog.Handler
	minSeverity slog.Level            // minimum severity level to log (severity >= minSeverity)
	vdefault    slog.Level            // default verbosity level for verbose logs (levels < LevelInfo)
	vmodules    map[string]slog.Level // per-module verbosity overrides
}

// NewGlogHandler returns a Handler that filters records according to glog-style
// severity and verbosity settings.  By default, it logs messages with level >= LevelInfo
// and suppresses verbose logs (levels < LevelInfo) until Verbosity is called.
func NewGlogHandler(h slog.Handler) *GlogHandler {
	return &GlogHandler{
		handler:     h,
		minSeverity: LevelInfo,
		vdefault:    LevelInfo,
		vmodules:    make(map[string]slog.Level),
	}
}

// Verbosity sets both the minimum severity and default verbosity levels.
// Messages with level >= v will be logged as severity; messages with level < LevelInfo
// will be logged if their level <= v.
func (g *GlogHandler) Verbosity(v slog.Level) {
	g.minSeverity = v
	g.vdefault = v
}

// Vmodule sets a per-file verbosity level according to the spec string of the form
// "pattern=level".  Multiple specs may be comma-separated.
func (g *GlogHandler) Vmodule(spec string) error {
	for _, entry := range strings.Split(spec, ",") {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		lvl, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		g.vmodules[parts[0]] = slog.Level(lvl)
	}
	return nil
}

// Enabled reports whether records at the given level should be logged or
// passed to Handle for further verbose filtering.
func (g *GlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Pass through severity or verbose logs to Handle for filtering
	return level >= g.minSeverity || level < LevelInfo
}

// Handle filters the record according to severity and verbosity (including vmodule) and
// forwards it to the underlying handler if allowed.
func (g *GlogHandler) Handle(ctx context.Context, r slog.Record) error {
	lvl := r.Level
	if lvl >= g.minSeverity {
		return g.handler.Handle(ctx, r)
	}
	if lvl < LevelInfo {
		// determine verbosity threshold (module override or default)
		vthr := g.vdefault
		// extract base file name from record PC
		if pc := r.PC; pc != 0 {
			frames := runtime.CallersFrames([]uintptr{pc})
			if fr, _ := frames.Next(); fr.File != "" {
				if mod, ok := g.vmodules[filepath.Base(fr.File)]; ok {
					vthr = mod
				}
			}
		}
		if lvl <= vthr {
			return g.handler.Handle(ctx, r)
		}
	}
	return nil
}

// WithAttrs returns a new glogHandler with the given attributes added to the
// underlying handler.
func (g *GlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &GlogHandler{
		handler:     g.handler.WithAttrs(attrs),
		minSeverity: g.minSeverity,
		vdefault:    g.vdefault,
		vmodules:    g.vmodules,
	}
}

// WithGroup returns a new glogHandler with the given group added to the
// underlying handler.
func (g *GlogHandler) WithGroup(name string) slog.Handler {
	return &GlogHandler{
		handler:     g.handler.WithGroup(name),
		minSeverity: g.minSeverity,
		vdefault:    g.vdefault,
		vmodules:    g.vmodules,
	}
}
