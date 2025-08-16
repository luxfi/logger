package log

import (
	"fmt"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Re-export zap types for compatibility
type (
	// Field is an alias for zap.Field for structured logging
	Field = zap.Field
	// Option is an alias for zap.Option
	Option = zap.Option
	// ObjectMarshaler is an alias for zapcore.ObjectMarshaler
	ObjectMarshaler = zapcore.ObjectMarshaler
	// ArrayMarshaler is an alias for zapcore.ArrayMarshaler
	ArrayMarshaler = zapcore.ArrayMarshaler
)

// Field constructors - re-export commonly used ones from zap
var (
	// String constructs a field with the given key and value.
	String = zap.String
	// Strings constructs a field that carries a slice of strings.
	Strings = zap.Strings
	// Int constructs a field with the given key and value.
	Int = zap.Int
	// Int64 constructs a field with the given key and value.
	Int64 = zap.Int64
	// Int32 constructs a field with the given key and value.
	Int32 = zap.Int32
	// Int16 constructs a field with the given key and value.
	Int16 = zap.Int16
	// Int8 constructs a field with the given key and value.
	Int8 = zap.Int8
	// Uint constructs a field with the given key and value.
	Uint = zap.Uint
	// Uint64 constructs a field with the given key and value.
	Uint64 = zap.Uint64
	// Uint32 constructs a field with the given key and value.
	Uint32 = zap.Uint32
	// Uint16 constructs a field with the given key and value.
	Uint16 = zap.Uint16
	// Uint8 constructs a field with the given key and value.
	Uint8 = zap.Uint8
	// Uintptr constructs a field with the given key and value.
	Uintptr = zap.Uintptr
	// Float64 constructs a field with the given key and value.
	Float64 = zap.Float64
	// Float32 constructs a field with the given key and value.
	Float32 = zap.Float32
	// Bool constructs a field that carries a bool.
	Bool = zap.Bool
	// Any takes a key and an arbitrary value and chooses the best way to represent
	// them as a field, falling back to a reflection-based approach only if necessary.
	Any = zap.Any
	// Err is shorthand for the common idiom NamedError("error", err).
	Err = zap.Error
	// NamedError constructs a field that lazily stores err.Error() under the
	// provided key. Errors which also implement fmt.Formatter (like those produced
	// by github.com/pkg/errors) will also have their verbose representation stored
	// under key+"Verbose". If passed a nil error, the field is a no-op.
	NamedError = zap.NamedError
	// Skip constructs a no-op field, which is often useful when handling invalid
	// inputs in other Field constructors.
	Skip = zap.Skip
	// Binary constructs a field that carries an opaque binary blob.
	Binary = zap.Binary
	// ByteString constructs a field that carries UTF-8 encoded text as a []byte.
	// To log opaque binary blobs (which aren't necessarily valid UTF-8), use
	// Binary.
	ByteString = zap.ByteString
	// Complex128 constructs a field that carries a complex number. Unlike most
	// numeric fields, this costs an allocation (to convert the complex128 to
	// interface{}).
	Complex128 = zap.Complex128
	// Complex64 constructs a field that carries a complex number. Unlike most
	// numeric fields, this costs an allocation (to convert the complex64 to
	// interface{}).
	Complex64 = zap.Complex64
	// Duration constructs a field with the given key and value. The encoder
	// controls how the duration is serialized.
	Duration = zap.Duration
	// Time constructs a field with the given key and value. The encoder
	// controls how the time is serialized.
	Time = zap.Time
	// Stack constructs a field that stores a stacktrace of the current goroutine
	// under provided key. Keep in mind that taking a stacktrace is eager and
	// expensive (relatively speaking); this function both makes an allocation and
	// takes about two microseconds.
	Stack = zap.Stack
	// StackSkip constructs a field similarly to Stack, but also skips the given
	// number of frames from the top of the stacktrace.
	StackSkip = zap.StackSkip
)

// Stringer constructs a field with the given key and the output of the value's
// String method. The Stringer's String method is called lazily.
func Stringer(key string, val fmt.Stringer) Field {
	return zap.Stringer(key, val)
}

// Reflect constructs a field with the given key and an arbitrary object. It uses
// an encoding-appropriate, reflection-based function to lazily serialize nearly
// any object into the logging context, but it's relatively slow and allocation-heavy.
// Outside tests, Any is always a better choice.
//
// If encoding fails (e.g., trying to serialize a map[int]string to JSON), Reflect
// includes the error message in the final log output.
func Reflect(key string, val interface{}) Field {
	return zap.Reflect(key, val)
}

// Namespace creates a named, isolated scope within the logger's context. All
// subsequent fields will be added to the new namespace.
//
// This helps prevent key collisions when injecting loggers into sub-components
// or third-party libraries.
func Namespace(key string) Field {
	return zap.Namespace(key)
}

// Inline constructs a Field that is similar to Object, but it
// will add the elements of the provided ObjectMarshaler to the
// current namespace.
func Inline(val ObjectMarshaler) Field {
	return zap.Inline(val)
}

// Object constructs a field with the given key and ObjectMarshaler. It
// provides a flexible, but still type-safe and efficient, way to add map- or
// struct-like user-defined types to the logging context. The struct's
// MarshalLogObject method is called lazily.
func Object(key string, val ObjectMarshaler) Field {
	return zap.Object(key, val)
}

// Array constructs a field with the given key and ArrayMarshaler. It provides
// a flexible, but still type-safe and efficient, way to add array-like types
// to the logging context. The struct's MarshalLogArray method is called
// lazily.
func Array(key string, val ArrayMarshaler) Field {
	return zap.Array(key, val)
}

// Timep constructs a field that carries a *time.Time. The returned Field will safely
// and explicitly represent `nil` when appropriate.
func Timep(key string, val *time.Time) Field {
	return zap.Timep(key, val)
}

// Durationp constructs a field that carries a *time.Duration. The returned Field will safely
// and explicitly represent `nil` when appropriate.
func Durationp(key string, val *time.Duration) Field {
	return zap.Durationp(key, val)
}

// UserString creates a field for user-provided strings that may need sanitization
func UserString(key, val string) Field {
	return zap.String(key, val)
}

// UserStrings creates a field for user-provided string slices that may need sanitization
func UserStrings(key string, vals []string) Field {
	return zap.Strings(key, vals)
}
