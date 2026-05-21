package executor

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"testing"
)

func TestWindsurfGRPCExtractFrames(t *testing.T) {
	first := []byte("one")
	second := []byte("two")
	combined := append(windsurfGRPCFrame(first), windsurfGRPCFrame(second)...)
	frames, err := windsurfExtractGRPCFrames(combined)
	if err != nil {
		t.Fatalf("extract frames: %v", err)
	}
	if len(frames) != 2 || string(frames[0]) != "one" || string(frames[1]) != "two" {
		t.Fatalf("frames = %#v, want one/two", frames)
	}
}

func TestWindsurfGRPCExtractCompressedGzipFrame(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("compressed payload")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	frame := make([]byte, 5+compressed.Len())
	frame[0] = 1
	binary.BigEndian.PutUint32(frame[1:5], uint32(compressed.Len()))
	copy(frame[5:], compressed.Bytes())

	frames, err := windsurfExtractGRPCFramesWithEncoding(frame, "gzip")
	if err != nil {
		t.Fatalf("extract compressed frame: %v", err)
	}
	if len(frames) != 1 || string(frames[0]) != "compressed payload" {
		t.Fatalf("frames = %#v, want compressed payload", frames)
	}
}

func TestWindsurfProtoStartCascadeRoundTrip(t *testing.T) {
	payload := windsurfWriteStringField(1, "cascade-123")
	got, err := windsurfParseStartCascadeResponse(payload)
	if err != nil {
		t.Fatalf("parse start response: %v", err)
	}
	if got != "cascade-123" {
		t.Fatalf("cascade id = %q, want cascade-123", got)
	}
}

func TestWindsurfProtoTrajectoryStepsParser(t *testing.T) {
	planner := windsurfWriteStringField(1, "hello")
	planner = append(planner, windsurfWriteStringField(3, "thinking")...)
	step := windsurfWriteVarintField(1, 15)
	step = append(step, windsurfWriteVarintField(4, 3)...)
	step = append(step, windsurfWriteMessageField(20, planner)...)
	resp := windsurfWriteMessageField(1, step)

	steps, err := windsurfParseTrajectorySteps(resp)
	if err != nil {
		t.Fatalf("parse steps: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("steps len = %d, want 1", len(steps))
	}
	if steps[0].Text != "hello" || steps[0].Thinking != "thinking" {
		t.Fatalf("step = %#v", steps[0])
	}
}
