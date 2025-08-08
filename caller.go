package log

import (
	"runtime"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"
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
	if !c.Enabled(ent.Level) {
		return ce
	}
	return c.Core.Check(ent, ce).AddCore(ent, c)
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
		if !isInternalFrame(f) {
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
	pkgs := getInternalPkgs()
	for _, p := range pkgs {
		if strings.HasPrefix(f.Function, p) {
			return true
		}
		// Match either versioned or unversioned module paths on disk.
		if strings.Contains(f.File, "/"+p+"@") || strings.Contains(f.File, "/"+p+"/") {
			return true
		}
	}
	return false
}