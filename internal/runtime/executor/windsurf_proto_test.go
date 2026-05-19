package executor

import "testing"

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
