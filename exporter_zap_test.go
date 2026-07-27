package log

import (
	"context"
	"encoding/json"
	"testing"

	sdklog "go.opentelemetry.io/otel/sdk/log"

	otellog "go.opentelemetry.io/otel/log"
)

// Attributes must survive the trip. A string arriving empty while an int
// arrives intact is the failure this pins: it looks like a working exporter
// and silently loses half the fields.
func TestValueAnyRoundTrip(t *testing.T) {
	cases := map[string]struct {
		in   otellog.Value
		want any
	}{
		"string":  {otellog.StringValue("api"), "api"},
		"int64":   {otellog.Int64Value(502), int64(502)},
		"bool":    {otellog.BoolValue(true), true},
		"float64": {otellog.Float64Value(1.5), 1.5},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := valueAny(c.in)
			if got != c.want {
				t.Fatalf("valueAny(%v [kind=%v]) = %#v, want %#v", c.in, c.in.Kind(), got, c.want)
			}
		})
	}
}

func TestValueAnySliceAndMap(t *testing.T) {
	sl := valueAny(otellog.SliceValue(otellog.StringValue("a"), otellog.Int64Value(2)))
	b, _ := json.Marshal(sl)
	if string(b) != `["a",2]` {
		t.Fatalf("slice = %s, want [\"a\",2]", b)
	}
	m := valueAny(otellog.MapValue(otellog.String("k", "v")))
	b, _ = json.Marshal(m)
	if string(b) != `{"k":"v"}` {
		t.Fatalf("map = %s, want {\"k\":\"v\"}", b)
	}
}

func TestValueStringRendersStructured(t *testing.T) {
	if got := valueString(otellog.StringValue("plain")); got != "plain" {
		t.Fatalf("string body = %q, want plain", got)
	}
	if got := valueString(otellog.Int64Value(7)); got != "7" {
		t.Fatalf("int body = %q, want 7", got)
	}
	if got := valueString(otellog.Value{}); got != "" {
		t.Fatalf("empty body = %q, want empty", got)
	}
}

// The MsgType is wire identity shared with the receiver; a change here breaks
// every deployed collector, so it is pinned rather than assumed.
func TestMsgTypeIsStable(t *testing.T) {
	if MsgLogBatch != 3 {
		t.Fatalf("MsgLogBatch = %d, want 3 (1=spans, 2=metrics)", MsgLogBatch)
	}
}

// The envelope must carry the type in the flags high byte, the way luxfi/zap
// frames it and the receiver reads it back.
func TestEncodeLogBatchTagsTheEnvelope(t *testing.T) {
	wire, err := encodeLogBatch([]byte(`{"records":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) < 16 {
		t.Fatalf("envelope is %d bytes, too short for a header", len(wire))
	}
	flags := uint16(wire[6]) | uint16(wire[7])<<8
	if got := flags >> 8; got != MsgLogBatch {
		t.Fatalf("msgType in flags = %d, want %d", got, MsgLogBatch)
	}
}

// toRecord is where a real Record's attributes are read. valueAny being correct
// in isolation does not prove the walk is.
//
// The record MUST come from a LoggerProvider. A hand-built sdklog.Record has
// attributeValueLengthLimit at its zero value, and the SDK treats >= 0 as a real
// limit — so every string attribute truncates to nothing while ints pass
// through, which looks exactly like a broken exporter. The provider's default is
// -1 (unlimited). This cost an hour; do not "simplify" it back to a bare Record.
func TestToRecordKeepsStringAttributes(t *testing.T) {
	var captured []sdklog.Record
	prov := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(recordSink{&captured}),
	)
	var rec otellog.Record
	rec.SetSeverityText("ERROR")
	rec.SetBody(otellog.StringValue("boom"))
	rec.AddAttributes(otellog.String("route", "api"), otellog.Int64("status", 502))
	prov.Logger("test").Emit(context.Background(), rec)
	if len(captured) != 1 {
		t.Fatalf("captured %d records, want 1", len(captured))
	}

	got := toRecord(&captured[0])
	if got.Attributes["route"] != "api" {
		t.Fatalf("route = %#v, want \"api\"", got.Attributes["route"])
	}
	if got.Attributes["status"] != int64(502) {
		t.Fatalf("status = %#v, want 502", got.Attributes["status"])
	}
	if got.Body != "boom" {
		t.Fatalf("body = %q, want boom", got.Body)
	}
}

// recordSink captures what the SDK hands an exporter.
type recordSink struct{ out *[]sdklog.Record }

func (s recordSink) OnEmit(_ context.Context, r *sdklog.Record) error {
	*s.out = append(*s.out, *r)
	return nil
}
func (s recordSink) Enabled(context.Context, sdklog.EnabledParameters) bool { return true }
func (s recordSink) Shutdown(context.Context) error                         { return nil }
func (s recordSink) ForceFlush(context.Context) error                       { return nil }
