// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// ZAP-native log exporter — the third wire beside traces and metrics.
//
// Records serialize to JSON inside a luxfi/zap envelope and ship over TCP to a
// ZAP-aware o11y collector (hanzo/o11y/pkg/zaplogreceiver). Zero
// google.golang.org/protobuf, zero OTLP, zero gRPC.
//
// Wire layout per export call:
//
//	zap envelope, MsgType=MsgLogBatch
//	└─ root object
//	   └─ field 0 (bytes): JSON-encoded LogBatch
//
// Before this existed, pushing logs meant an OTLP exporter, and OTLP carries
// protobuf and gRPC on either flavour — otlploghttp and otlploggrpc share
// otlpconfig. A service that wanted its logs off the box had no other door.

package log

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/zap"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// MsgLogBatch is the ZAP MsgType that carries a LogBatch payload.
//
// Stable wire ID on the ZAP bus, append-only: 1 is spans (luxfi/trace) and 2 is
// metrics (luxfi/metric), so logs take 3. Renumbering breaks every deployed
// collector in lockstep.
const MsgLogBatch uint16 = 3

// The canonical o11y ZAP port, shared with the trace and metric wires.
const defaultEndpoint = "127.0.0.1:4317"

// LogBatch is the JSON shape that rides inside the ZAP envelope's payload.
// One batch per Export call.
type LogBatch struct {
	AppName  string            `json:"appName,omitempty"`
	Version  string            `json:"version,omitempty"`
	Resource map[string]string `json:"resource,omitempty"`
	Records  []LogRecord       `json:"records"`
}

// LogRecord is the wire shape for a single sdklog.Record.
type LogRecord struct {
	TimeUnixNs         int64          `json:"timeUnixNs"`
	ObservedTimeUnixNs int64          `json:"observedTimeUnixNs,omitempty"`
	Severity           int            `json:"severity,omitempty"`
	SeverityText       string         `json:"severityText,omitempty"`
	Body               string         `json:"body,omitempty"`
	Attributes         map[string]any `json:"attributes,omitempty"`
	TraceID            string         `json:"traceId,omitempty"`
	SpanID             string         `json:"spanId,omitempty"`
	EventName          string         `json:"eventName,omitempty"`
}

// ZAPExporterConfig drives the exporter.
type ZAPExporterConfig struct {
	// Endpoint is the collector address (host:port). A scheme or path has no
	// meaning on this wire; empty defaults to the canonical o11y port.
	Endpoint string

	// AppName + Version land in every emitted batch's metadata.
	AppName string
	Version string

	// Resource attributes shipped with every batch.
	Resource map[string]string
}

// ZAPExporter implements go.opentelemetry.io/otel/sdk/log.Exporter.
type ZAPExporter struct {
	cfg  ZAPExporterConfig
	node *zap.Node

	mu       sync.Mutex
	serverID string
	shutdown bool
}

var _ sdklog.Exporter = (*ZAPExporter)(nil)

// NewZAPExporter dials the collector.
//
// Returns the exporter even if the initial connect fails — the next Export
// retries. This matches the trace exporter's posture: fire-and-forget means
// startup never fails on collector reachability.
func NewZAPExporter(cfg ZAPExporterConfig) (*ZAPExporter, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaultEndpoint
	}
	node := zap.NewNode(zap.NodeConfig{
		NodeID:      fmt.Sprintf("log-%s", cfg.AppName),
		ServiceType: "_o11y._tcp",
	})
	e := &ZAPExporter{cfg: cfg, node: node}
	_ = e.connect()
	return e, nil
}

// connect is idempotent under the mutex — called from New and from Export when
// an earlier connect failed.
func (e *ZAPExporter) connect() error {
	if err := e.node.ConnectDirect(e.cfg.Endpoint); err != nil {
		return err
	}
	peers := e.node.Peers()
	if len(peers) == 0 {
		return fmt.Errorf("log zap exporter: connected but no peer ID for %s", e.cfg.Endpoint)
	}
	e.serverID = peers[0]
	return nil
}

// Export serializes records to JSON, wraps them in a ZAP envelope, and fires
// them over the cached connection. Fire-and-forget — no response is expected.
func (e *ZAPExporter) Export(ctx context.Context, records []sdklog.Record) error {
	if len(records) == 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shutdown {
		return errors.New("log zap exporter: shut down")
	}
	if e.serverID == "" {
		if err := e.connect(); err != nil {
			return err
		}
	}

	batch := LogBatch{
		AppName:  e.cfg.AppName,
		Version:  e.cfg.Version,
		Resource: e.cfg.Resource,
		Records:  make([]LogRecord, 0, len(records)),
	}
	for i := range records {
		batch.Records = append(batch.Records, toRecord(&records[i]))
	}

	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("log zap exporter: marshal batch: %w", err)
	}
	wire, err := encodeLogBatch(payload)
	if err != nil {
		return err
	}
	msg, err := zap.Parse(wire)
	if err != nil {
		return fmt.Errorf("log zap exporter: parse outgoing: %w", err)
	}
	if err := e.node.Send(ctx, e.serverID, msg); err != nil {
		// Connection died — invalidate so the next call reconnects. Telemetry
		// must not fail the caller, so this is swallowed like the trace wire.
		e.serverID = ""
		return nil
	}
	return nil
}

// ForceFlush has nothing to flush: Export sends synchronously.
func (e *ZAPExporter) ForceFlush(context.Context) error { return nil }

func (e *ZAPExporter) Shutdown(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shutdown {
		return nil
	}
	e.shutdown = true
	e.node.Stop()
	return nil
}

func toRecord(r *sdklog.Record) LogRecord {
	out := LogRecord{
		TimeUnixNs:   r.Timestamp().UnixNano(),
		Severity:     int(r.Severity()),
		SeverityText: r.SeverityText(),
		Body:         valueString(r.Body()),
		EventName:    r.EventName(),
	}
	if o := r.ObservedTimestamp(); !o.IsZero() {
		out.ObservedTimeUnixNs = o.UnixNano()
	}
	if sc := r.TraceID(); sc.IsValid() {
		out.TraceID = sc.String()
	}
	if sc := r.SpanID(); sc.IsValid() {
		out.SpanID = sc.String()
	}
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		if out.Attributes == nil {
			out.Attributes = make(map[string]any)
		}
		out.Attributes[kv.Key] = valueAny(kv.Value)
		return true
	})
	return out
}

// valueString renders a body. A log body is read by humans and by substring
// queries, so anything structured becomes its JSON rather than a Go dump.
func valueString(v otellog.Value) string {
	switch v.Kind() {
	case otellog.KindString:
		return v.AsString()
	case otellog.KindEmpty:
		return ""
	default:
		b, err := json.Marshal(valueAny(v))
		if err != nil {
			return fmt.Sprint(valueAny(v))
		}
		return string(b)
	}
}

func valueAny(v otellog.Value) any {
	switch v.Kind() {
	case otellog.KindBool:
		return v.AsBool()
	case otellog.KindFloat64:
		return v.AsFloat64()
	case otellog.KindInt64:
		return v.AsInt64()
	case otellog.KindString:
		return v.AsString()
	case otellog.KindBytes:
		return v.AsBytes()
	case otellog.KindSlice:
		s := v.AsSlice()
		out := make([]any, 0, len(s))
		for _, e := range s {
			out = append(out, valueAny(e))
		}
		return out
	case otellog.KindMap:
		m := v.AsMap()
		out := make(map[string]any, len(m))
		for _, kv := range m {
			out[kv.Key] = valueAny(kv.Value)
		}
		return out
	default:
		return nil
	}
}

// encodeLogBatch wraps a JSON payload in a ZAP envelope tagged MsgLogBatch.
//
// The MsgType goes in the upper 8 bits of the ZAP flags field — luxfi/zap's own
// layout, and the receiver reads it back out of the same bits.
func encodeLogBatch(payload []byte) ([]byte, error) {
	b := zap.NewBuilder(len(payload) + 128)
	root := b.StartObject(8)
	root.SetBytes(0, payload)
	root.FinishAsRoot()
	return b.FinishWithFlags(MsgLogBatch << 8), nil
}
