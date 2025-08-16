package log

import (
	"runtime"
	"strings"
	"sync/atomic"

	"go.uber.org/zap/zapcore"
)

// internalPkgList holds the set of packages we should treat as "internal" to logging,
// so their frames are skipped when reporting the call site.
// We start with github.com/luxfi/log and zap internals; callers can add more at runtime.
var internalPkgList atomic.Value // stores []string

func init() {
	internalPkgList.Store([]string{
		"github.com/luxfi/log",
		"go.uber.org/zap",
		"go.uber.org/zap/zapcore",
	})
}

// RegisterInternalPackages lets applications add package prefixes that should be
// treated as "internal" (wrappers, adapters, etc.). Calls are concurrency-safe.
func RegisterInternalPackages(pkgs ...string) {
	if len(pkgs) == 0 {
		return
	}
	cur := internalPkgList.Load().([]string)
	cp := make([]string, 0, len(cur)+len(pkgs))
	cp = append(cp, cur...)
	cp = append(cp, pkgs...)
	internalPkgList.Store(cp)
}

func getInternalPkgs() []string {
	return internalPkgList.Load().([]string)
}

// callerCore wraps a zapcore.Core and replaces Entry.Caller with the first
// frame found outside of internal packages.
type callerCore struct{ zapcore.Core }

func (c callerCore) With(fields []zapcore.Field) zapcore.Core {
	return callerCore{Core: c.Core.With(fields)}
}

func (c callerCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	// Check if the wrapped core wants to log this
	if !c.Enabled(ent.Level) {
		return ce
	}
	// Create a new checked entry with just our wrapper
	// This ensures we're the only core that processes the entry
	return ce.AddCore(ent, c)
}

func (c callerCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	if ec, ok := firstExternalCaller(); ok {
		ent.Caller = ec
	}
	return c.Core.Write(ent, fields)
}

// firstExternalCaller scans the stack and returns the first frame that is not
// part of this logging package or zap internals.
func firstExternalCaller() (zapcore.EntryCaller, bool) {
	const maxDepth = 64
	var pcs [maxDepth]uintptr

	// Skip runtime.Callers and this function.
	n := runtime.Callers(2, pcs[:])
	if n == 0 {
		return zapcore.EntryCaller{}, false
	}

	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()

		// Skip runtime frames (Go 1.24+ compatibility)
		if strings.Contains(f.File, "/runtime/") || strings.Contains(f.Function, "runtime.") {
			if !more {
				break
			}
			continue
		}

		// Skip internal frames (log module, zap, etc.)
		if !isInternalFrame(f) {
			// Also skip testing framework if we're in a test
			if !strings.Contains(f.File, "/testing/") && !strings.Contains(f.File, "_test.go") {
				return zapcore.EntryCaller{
					Defined: true,
					PC:      f.PC,
					File:    f.File,
					Line:    f.Line,
				}, true
			}
			// In tests, if we hit testing framework, keep looking
			if strings.Contains(f.File, "/testing/") {
				if !more {
					break
				}
				continue
			}
			// Found a test file, use it
			return zapcore.EntryCaller{
				Defined: true,
				PC:      f.PC,
				File:    f.File,
				Line:    f.Line,
			}, true
		}
		if !more {
			break
		}
	}
	return zapcore.EntryCaller{}, false
}

func isInternalFrame(f runtime.Frame) bool {
	// f.Function is of the form: "github.com/org/pkg.(*type).method"
	// f.File can include module versions: ".../github.com/org/pkg@v1.2.3/file.go"
	// or shortened forms like "log@v1.0.6/logger.go"

	// First check: is this frame from log@v*/ files?
	// This catches the common case of "log@v1.0.6/logger.go:196"
	if strings.Contains(f.File, "log@v") {
		return true
	}

	// Check against our internal package list
	pkgs := getInternalPkgs()
	for _, p := range pkgs {
		// Check function name first
		if strings.HasPrefix(f.Function, p) {
			return true
		}
		// Match either versioned or unversioned module paths on disk.
		if strings.Contains(f.File, "/"+p+"@") || strings.Contains(f.File, "/"+p+"/") {
			return true
		}
		// Also check for versioned module paths like "log@v1.0.5"
		// This handles cases where the module is loaded with a version tag
		if idx := strings.LastIndex(p, "/"); idx >= 0 {
			moduleName := p[idx+1:]
			// Check if file contains the module name with version (e.g., "log@v1.0.5")
			if strings.Contains(f.File, "/"+moduleName+"@") || strings.Contains(f.File, moduleName+"@") {
				return true
			}
			// Also check for relative paths like "log/logger.go"
			if strings.HasPrefix(f.File, moduleName+"/") {
				return true
			}
		}
	}
	// Check for github.com/luxfi/log in any form (versioned or not)
	if strings.Contains(f.File, "github.com/luxfi/log") {
		return true
	}
	// Check for any log module files (catches relative paths)
	if strings.HasPrefix(f.File, "log/") {
		return true
	}
	return false
}
