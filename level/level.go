package level

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap/zapcore"
)

// Level represents a logging level
type Level int8

const (
	Verbo Level = iota - 9
	Debug
	Trace
	Info
	Warn
	Error
	Fatal
	Off
)

var ErrUnknownLevel = errors.New("unknown log level")

// String returns the string representation of a Level
func (l Level) String() string {
	switch l {
	case Off:
		return "OFF"
	case Fatal:
		return "FATAL"
	case Error:
		return "ERROR"
	case Warn:
		return "WARN"
	case Info:
		return "INFO"
	case Trace:
		return "TRACE"
	case Debug:
		return "DEBUG"
	case Verbo:
		return "VERBO"
	default:
		return "UNKNO"
	}
}

// LowerString returns the lowercase string representation of a Level
func (l Level) LowerString() string {
	return strings.ToLower(l.String())
}

// MarshalJSON marshals the Level to JSON
func (l Level) MarshalJSON() ([]byte, error) {
	return json.Marshal(l.String())
}

// UnmarshalJSON unmarshals the Level from JSON
func (l *Level) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	var err error
	*l, err = ToLevel(str)
	return err
}

// ToLevel converts a string to a Level
func ToLevel(l string) (Level, error) {
	switch strings.ToUpper(l) {
	case "OFF":
		return Off, nil
	case "FATAL":
		return Fatal, nil
	case "ERROR":
		return Error, nil
	case "WARN":
		return Warn, nil
	case "INFO":
		return Info, nil
	case "TRACE":
		return Trace, nil
	case "DEBUG":
		return Debug, nil
	case "VERBO":
		return Verbo, nil
	default:
		return Off, fmt.Errorf("%w: %q", ErrUnknownLevel, l)
	}
}

// ToZapLevel converts our Level to zapcore.Level
func ToZapLevel(level Level) zapcore.Level {
	return zapcore.Level(level)
}

// FromZapLevel converts zapcore.Level to our Level
func FromZapLevel(level zapcore.Level) Level {
	return Level(level)
}