package executor

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"time"

	"github.com/google/uuid"
)

// Constants from WindsurfAPI src/client.js. The protobuf builders/parsers from
// src/windsurf.js should be ported here in small, testable chunks.
const windsurfLanguageServerService = "/exa.language_server_pb.LanguageServerService"

const (
	windsurfRPCGetUserStatus          = windsurfLanguageServerService + "/GetUserStatus"
	windsurfRPCRawGetChatMessage      = windsurfLanguageServerService + "/RawGetChatMessage"
	windsurfRPCInitializePanelState   = windsurfLanguageServerService + "/InitializePanelState"
	windsurfRPCHeartbeat              = windsurfLanguageServerService + "/Heartbeat"
	windsurfRPCAddTrackedWorkspace    = windsurfLanguageServerService + "/AddTrackedWorkspace"
	windsurfRPCUpdateWorkspaceTrust   = windsurfLanguageServerService + "/UpdateWorkspaceTrust"
	windsurfRPCStartCascade           = windsurfLanguageServerService + "/StartCascade"
	windsurfRPCSendUserCascadeMessage = windsurfLanguageServerService + "/SendUserCascadeMessage"
	windsurfRPCGetTrajectory          = windsurfLanguageServerService + "/GetTrajectory"
	windsurfRPCGetTrajectorySteps     = windsurfLanguageServerService + "/GetTrajectorySteps"
	windsurfRPCGetGeneratorMetadata   = windsurfLanguageServerService + "/GetGeneratorMetadata"
	windsurfRPCGetCascadeModelConfigs = windsurfLanguageServerService + "/GetCascadeModelConfigs"
)

type windsurfProtoField struct {
	Number   int
	WireType int
	Varint   uint64
	Bytes    []byte
	Fixed32  uint32
	Fixed64  uint64
}

func windsurfWriteVarintField(number int, value uint64) []byte {
	out := windsurfEncodeVarint(uint64(number<<3) | 0)
	return append(out, windsurfEncodeVarint(value)...)
}

func windsurfWriteBoolField(number int, value bool) []byte {
	if value {
		return windsurfWriteVarintField(number, 1)
	}
	return windsurfWriteVarintField(number, 0)
}

func windsurfWriteStringField(number int, value string) []byte {
	return windsurfWriteBytesField(number, []byte(value))
}

func windsurfWriteBytesField(number int, value []byte) []byte {
	out := windsurfEncodeVarint(uint64(number<<3) | 2)
	out = append(out, windsurfEncodeVarint(uint64(len(value)))...)
	out = append(out, value...)
	return out
}

func windsurfWriteMessageField(number int, value []byte) []byte {
	return windsurfWriteBytesField(number, value)
}

func windsurfEncodeVarint(value uint64) []byte {
	out := make([]byte, 0, 10)
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	out = append(out, byte(value))
	return out
}

func windsurfReadVarint(buf []byte, offset int) (uint64, int, error) {
	var value uint64
	for shift := 0; shift < 64; shift += 7 {
		if offset >= len(buf) {
			return 0, offset, fmt.Errorf("windsurf proto: truncated varint")
		}
		b := buf[offset]
		offset++
		value |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return value, offset, nil
		}
	}
	return 0, offset, fmt.Errorf("windsurf proto: varint overflow")
}

func windsurfParseFields(buf []byte) ([]windsurfProtoField, error) {
	fields := make([]windsurfProtoField, 0, 16)
	offset := 0
	for offset < len(buf) {
		tag, next, err := windsurfReadVarint(buf, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		number := int(tag >> 3)
		wireType := int(tag & 7)
		field := windsurfProtoField{Number: number, WireType: wireType}
		switch wireType {
		case 0:
			field.Varint, offset, err = windsurfReadVarint(buf, offset)
			if err != nil {
				return nil, err
			}
		case 1:
			if offset+8 > len(buf) {
				return nil, fmt.Errorf("windsurf proto: truncated fixed64")
			}
			field.Fixed64 = binary.LittleEndian.Uint64(buf[offset : offset+8])
			offset += 8
		case 2:
			size, afterSize, errRead := windsurfReadVarint(buf, offset)
			if errRead != nil {
				return nil, errRead
			}
			offset = afterSize
			if size > uint64(len(buf)-offset) {
				return nil, fmt.Errorf("windsurf proto: truncated length-delimited field")
			}
			field.Bytes = buf[offset : offset+int(size)]
			offset += int(size)
		case 5:
			if offset+4 > len(buf) {
				return nil, fmt.Errorf("windsurf proto: truncated fixed32")
			}
			field.Fixed32 = binary.LittleEndian.Uint32(buf[offset : offset+4])
			offset += 4
		default:
			return nil, fmt.Errorf("windsurf proto: unsupported wire type %d", wireType)
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func windsurfField(fields []windsurfProtoField, number, wireType int) (windsurfProtoField, bool) {
	for _, field := range fields {
		if field.Number == number && (wireType < 0 || field.WireType == wireType) {
			return field, true
		}
	}
	return windsurfProtoField{}, false
}

func windsurfFields(fields []windsurfProtoField, number int) []windsurfProtoField {
	out := make([]windsurfProtoField, 0, 4)
	for _, field := range fields {
		if field.Number == number {
			out = append(out, field)
		}
	}
	return out
}

func windsurfEncodeTimestamp(now time.Time) []byte {
	if now.IsZero() {
		now = time.Now()
	}
	secs := uint64(now.Unix())
	nanos := uint64(now.Nanosecond())
	out := windsurfWriteVarintField(1, secs)
	if nanos > 0 {
		out = append(out, windsurfWriteVarintField(2, nanos)...)
	}
	return out
}

func windsurfBuildMetadata(apiKey, sessionID string) []byte {
	version := firstNonEmpty("", "2.0.67")
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macos"
	}
	hardware := "x86_64"
	if runtime.GOARCH == "arm64" {
		hardware = "arm64"
	}
	requestID := uint64(time.Now().UnixNano()) & ((1 << 48) - 1)
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	out := windsurfWriteStringField(1, "windsurf")
	out = append(out, windsurfWriteStringField(2, version)...)
	out = append(out, windsurfWriteStringField(3, apiKey)...)
	out = append(out, windsurfWriteStringField(4, "en")...)
	out = append(out, windsurfWriteStringField(5, osName)...)
	out = append(out, windsurfWriteStringField(7, version)...)
	out = append(out, windsurfWriteStringField(8, hardware)...)
	out = append(out, windsurfWriteVarintField(9, requestID)...)
	out = append(out, windsurfWriteStringField(10, sessionID)...)
	out = append(out, windsurfWriteStringField(12, "windsurf")...)
	return out
}

func windsurfBuildInitializePanelStateRequest(apiKey, sessionID string, trusted bool) []byte {
	out := windsurfWriteMessageField(1, windsurfBuildMetadata(apiKey, sessionID))
	out = append(out, windsurfWriteBoolField(3, trusted)...)
	return out
}

func windsurfBuildHeartbeatRequest(apiKey, sessionID string) []byte {
	return windsurfWriteMessageField(1, windsurfBuildMetadata(apiKey, sessionID))
}

func windsurfBuildAddTrackedWorkspaceRequest(workspacePath string) []byte {
	return windsurfWriteStringField(1, workspacePath)
}

func windsurfBuildUpdateWorkspaceTrustRequest(apiKey, sessionID string, trusted bool) []byte {
	out := windsurfWriteMessageField(1, windsurfBuildMetadata(apiKey, sessionID))
	out = append(out, windsurfWriteBoolField(2, trusted)...)
	return out
}

func windsurfBuildStartCascadeRequest(apiKey, sessionID string) []byte {
	out := windsurfWriteMessageField(1, windsurfBuildMetadata(apiKey, sessionID))
	out = append(out, windsurfWriteVarintField(4, 1)...)
	out = append(out, windsurfWriteVarintField(5, 1)...)
	return out
}

func windsurfBuildSendCascadeMessageRequest(apiKey, cascadeID, text string, spec windsurfModelSpec, sessionID, toolPreamble string) ([]byte, error) {
	config, err := windsurfBuildCascadeConfig(spec, toolPreamble)
	if err != nil {
		return nil, err
	}
	out := windsurfWriteStringField(1, cascadeID)
	out = append(out, windsurfWriteMessageField(2, windsurfWriteStringField(1, text))...)
	out = append(out, windsurfWriteMessageField(3, windsurfBuildMetadata(apiKey, sessionID))...)
	out = append(out, windsurfWriteMessageField(5, config)...)
	return out, nil
}

func windsurfBuildCascadeConfig(spec windsurfModelSpec, toolPreamble string) ([]byte, error) {
	if spec.ModelUID == "" && spec.EnumValue <= 0 {
		return nil, fmt.Errorf("windsurf cascade config: missing model uid/enum for %q", spec.ID)
	}

	mode := uint64(3)
	if toolPreamble == "" {
		mode = 3
	}
	conversational := windsurfWriteVarintField(4, mode)
	if toolPreamble != "" {
		section := windsurfWriteVarintField(1, 1)
		section = append(section, windsurfWriteStringField(2, toolPreamble+"\n\nReturn exactly one tool call when a tool is needed. Do not fabricate tool results.")...)
		conversational = append(conversational, windsurfWriteMessageField(12, section)...)
		comm := windsurfWriteVarintField(1, 1)
		comm = append(comm, windsurfWriteStringField(2, "Use client-side tools only by emitting the requested tool call format. Otherwise answer directly.")...)
		conversational = append(conversational, windsurfWriteMessageField(13, comm)...)
	} else {
		noTools := windsurfWriteVarintField(1, 1)
		noTools = append(noTools, windsurfWriteStringField(2, "No tools are available.")...)
		conversational = append(conversational, windsurfWriteMessageField(10, noTools)...)
		additional := windsurfWriteVarintField(1, 1)
		additional = append(additional, windsurfWriteStringField(2, "Answer as a plain chat API. Do not claim to inspect local files or run commands unless the user pasted the relevant content.")...)
		conversational = append(conversational, windsurfWriteMessageField(12, additional)...)
		comm := windsurfWriteVarintField(1, 1)
		comm = append(comm, windsurfWriteStringField(2, "Respond directly and concisely in the user's language.")...)
		conversational = append(conversational, windsurfWriteMessageField(13, comm)...)
	}

	planner := windsurfWriteMessageField(2, conversational)
	if spec.ModelUID != "" {
		planner = append(planner, windsurfWriteStringField(35, spec.ModelUID)...)
		planner = append(planner, windsurfWriteStringField(34, spec.ModelUID)...)
	}
	if spec.EnumValue > 0 {
		planner = append(planner, windsurfWriteMessageField(15, windsurfWriteVarintField(1, uint64(spec.EnumValue)))...)
		planner = append(planner, windsurfWriteVarintField(1, uint64(spec.EnumValue))...)
	}
	planner = append(planner, windsurfWriteVarintField(6, 32768)...)
	if toolPreamble == "" {
		emptySection := windsurfWriteVarintField(1, 1)
		emptySection = append(emptySection, windsurfWriteStringField(2, "")...)
		planner = append(planner, windsurfWriteMessageField(11, emptySection)...)
	}

	memory := windsurfWriteBoolField(1, false)
	brain := windsurfWriteVarintField(1, 1)
	brain = append(brain, windsurfWriteMessageField(6, windsurfWriteMessageField(6, nil))...)

	out := windsurfWriteMessageField(1, planner)
	out = append(out, windsurfWriteMessageField(5, memory)...)
	out = append(out, windsurfWriteMessageField(7, brain)...)
	return out, nil
}

func windsurfBuildGetTrajectoryStepsRequest(cascadeID string, offset int) []byte {
	out := windsurfWriteStringField(1, cascadeID)
	if offset > 0 {
		out = append(out, windsurfWriteVarintField(2, uint64(offset))...)
	}
	return out
}

func windsurfBuildGetTrajectoryRequest(cascadeID string) []byte {
	return windsurfWriteStringField(1, cascadeID)
}

func windsurfParseStartCascadeResponse(buf []byte) (string, error) {
	fields, err := windsurfParseFields(buf)
	if err != nil {
		return "", err
	}
	if field, ok := windsurfField(fields, 1, 2); ok {
		return string(field.Bytes), nil
	}
	return "", nil
}

func windsurfParseTrajectoryStatus(buf []byte) (int, error) {
	fields, err := windsurfParseFields(buf)
	if err != nil {
		return 0, err
	}
	if field, ok := windsurfField(fields, 2, 0); ok {
		return int(field.Varint), nil
	}
	return 0, nil
}

type windsurfTrajectoryStep struct {
	Type      int
	Status    int
	Text      string
	Thinking  string
	ErrorText string
	ToolCalls []windsurfToolCall
	Usage     *windsurfUsage
}

type windsurfUsage struct {
	InputTokens      int
	OutputTokens     int
	CacheWriteTokens int
	CacheReadTokens  int
}

type windsurfToolCall struct {
	ID            string
	Name          string
	ArgumentsJSON string
	Result        string
	Native        bool
}

func windsurfParseTrajectorySteps(buf []byte) ([]windsurfTrajectoryStep, error) {
	fields, err := windsurfParseFields(buf)
	if err != nil {
		return nil, err
	}
	stepFields := windsurfFields(fields, 1)
	steps := make([]windsurfTrajectoryStep, 0, len(stepFields))
	for _, rawStep := range stepFields {
		if rawStep.WireType != 2 {
			continue
		}
		sf, errParse := windsurfParseFields(rawStep.Bytes)
		if errParse != nil {
			return nil, errParse
		}
		step := windsurfTrajectoryStep{}
		if f, ok := windsurfField(sf, 1, 0); ok {
			step.Type = int(f.Varint)
		}
		if f, ok := windsurfField(sf, 4, 0); ok {
			step.Status = int(f.Varint)
		}
		if metaField, ok := windsurfField(sf, 5, 2); ok {
			step.Usage = windsurfParseStepUsage(metaField.Bytes)
		}
		if plannerField, ok := windsurfField(sf, 20, 2); ok {
			pf, errPlanner := windsurfParseFields(plannerField.Bytes)
			if errPlanner != nil {
				return nil, errPlanner
			}
			response := ""
			if f, okText := windsurfField(pf, 1, 2); okText {
				response = string(f.Bytes)
			}
			if f, okModified := windsurfField(pf, 8, 2); okModified && len(f.Bytes) > 0 {
				response = string(f.Bytes)
			}
			step.Text = response
			if f, okThinking := windsurfField(pf, 3, 2); okThinking {
				step.Thinking = string(f.Bytes)
			}
		}
		step.ToolCalls = append(step.ToolCalls, windsurfParseNativeToolCalls(sf, len(steps))...)
		step.ErrorText = windsurfParseStepError(sf)
		steps = append(steps, step)
	}
	return steps, nil
}

func windsurfParseStepUsage(meta []byte) *windsurfUsage {
	fields, err := windsurfParseFields(meta)
	if err != nil {
		return nil
	}
	usageField, ok := windsurfField(fields, 9, 2)
	if !ok {
		return nil
	}
	usageFields, err := windsurfParseFields(usageField.Bytes)
	if err != nil {
		return nil
	}
	read := func(number int) int {
		if f, okField := windsurfField(usageFields, number, 0); okField {
			return int(f.Varint)
		}
		return 0
	}
	usage := &windsurfUsage{
		InputTokens:      read(2),
		OutputTokens:     read(3),
		CacheWriteTokens: read(4),
		CacheReadTokens:  read(5),
	}
	if usage.InputTokens == 0 && usage.OutputTokens == 0 && usage.CacheReadTokens == 0 && usage.CacheWriteTokens == 0 {
		return nil
	}
	return usage
}

func windsurfParseStepError(fields []windsurfProtoField) string {
	for _, number := range []int{24, 31} {
		field, ok := windsurfField(fields, number, 2)
		if !ok {
			continue
		}
		if number == 24 {
			wrapped, err := windsurfParseFields(field.Bytes)
			if err == nil {
				if inner, okInner := windsurfField(wrapped, 3, 2); okInner {
					if text := windsurfReadErrorDetails(inner.Bytes); text != "" {
						return text
					}
				}
			}
			continue
		}
		if text := windsurfReadErrorDetails(field.Bytes); text != "" {
			return text
		}
	}
	return ""
}

func windsurfReadErrorDetails(buf []byte) string {
	fields, err := windsurfParseFields(buf)
	if err != nil {
		return ""
	}
	for _, number := range []int{1, 2, 3} {
		if field, ok := windsurfField(fields, number, 2); ok {
			return string(field.Bytes)
		}
	}
	return ""
}

func windsurfParseNativeToolCalls(fields []windsurfProtoField, index int) []windsurfToolCall {
	kinds := []struct {
		field int
		name  string
	}{
		{14, "view_file"},
		{15, "list_directory"},
		{23, "write_to_file"},
		{28, "run_command"},
		{13, "grep_search"},
		{34, "find"},
		{105, "grep_search_v2"},
	}
	out := make([]windsurfToolCall, 0)
	for _, kind := range kinds {
		field, ok := windsurfField(fields, kind.field, 2)
		if !ok {
			continue
		}
		args := "{}"
		result := ""
		body, err := windsurfParseFields(field.Bytes)
		if err == nil {
			switch kind.name {
			case "run_command":
				command := windsurfStringField(body, 23)
				if command == "" {
					command = windsurfStringField(body, 1)
				}
				args = fmt.Sprintf(`{"command_line":%q,"cwd":%q}`, command, windsurfStringField(body, 2))
				result = windsurfStringField(body, 4)
			case "view_file":
				args = fmt.Sprintf(`{"absolute_path_uri":%q}`, windsurfStringField(body, 1))
				result = windsurfStringField(body, 4)
			case "list_directory":
				args = fmt.Sprintf(`{"directory_path_uri":%q}`, windsurfStringField(body, 1))
			case "grep_search_v2":
				args = fmt.Sprintf(`{"pattern":%q,"path":%q}`, windsurfStringField(body, 2), windsurfStringField(body, 3))
				result = windsurfStringField(body, 15)
			case "find":
				args = fmt.Sprintf(`{"pattern":%q,"search_directory":%q}`, windsurfStringField(body, 1), windsurfStringField(body, 10))
				result = windsurfStringField(body, 11)
			}
		}
		out = append(out, windsurfToolCall{
			ID:            fmt.Sprintf("native:%s:%d", kind.name, index),
			Name:          kind.name,
			ArgumentsJSON: args,
			Result:        result,
			Native:        true,
		})
	}
	return out
}

func windsurfStringField(fields []windsurfProtoField, number int) string {
	if field, ok := windsurfField(fields, number, 2); ok {
		return string(field.Bytes)
	}
	return ""
}

func windsurfFixed32Float(field windsurfProtoField) float32 {
	return math.Float32frombits(field.Fixed32)
}
