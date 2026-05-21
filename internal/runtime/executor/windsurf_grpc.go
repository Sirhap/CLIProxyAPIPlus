package executor

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// windsurfGRPCFrame mirrors WindsurfAPI src/grpc.js grpcFrame(): one byte
// compression flag followed by a uint32 big-endian protobuf payload length.
func windsurfGRPCFrame(payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

func windsurfStripGRPCFrame(frame []byte, encoding string) ([]byte, error) {
	if len(frame) < 5 {
		return frame, nil
	}
	compressed := frame[0] != 0
	size := int(binary.BigEndian.Uint32(frame[1:5]))
	if size < 0 || len(frame) < 5+size {
		return nil, fmt.Errorf("windsurf grpc: incomplete frame")
	}
	return windsurfDecodeGRPCPayload(frame[5:5+size], compressed, encoding)
}

func windsurfExtractGRPCFrames(buf []byte) ([][]byte, error) {
	return windsurfExtractGRPCFramesWithEncoding(buf, "identity")
}

func windsurfExtractGRPCFramesWithEncoding(buf []byte, encoding string) ([][]byte, error) {
	frames := make([][]byte, 0, 1)
	offset := 0
	for offset+5 <= len(buf) {
		compressed := buf[offset] != 0
		size := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
		if size < 0 || offset+5+size > len(buf) {
			return nil, fmt.Errorf("windsurf grpc: incomplete frame")
		}
		payload, err := windsurfDecodeGRPCPayload(buf[offset+5:offset+5+size], compressed, encoding)
		if err != nil {
			return nil, err
		}
		frames = append(frames, payload)
		offset += 5 + size
	}
	if offset != len(buf) {
		return nil, fmt.Errorf("windsurf grpc: trailing partial frame")
	}
	return frames, nil
}

func windsurfDecodeGRPCPayload(payload []byte, compressed bool, encoding string) ([]byte, error) {
	if !compressed {
		return payload, nil
	}
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "", "identity":
		return nil, fmt.Errorf("windsurf grpc: compressed frame missing grpc-encoding")
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("windsurf grpc: gzip frame: %w", err)
		}
		defer reader.Close()
		out, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("windsurf grpc: read gzip frame: %w", err)
		}
		return out, nil
	case "deflate":
		reader, err := zlib.NewReader(bytes.NewReader(payload))
		if err == nil {
			defer reader.Close()
			out, readErr := io.ReadAll(reader)
			if readErr != nil {
				return nil, fmt.Errorf("windsurf grpc: read deflate frame: %w", readErr)
			}
			return out, nil
		}
		rawReader := flate.NewReader(bytes.NewReader(payload))
		defer rawReader.Close()
		out, rawErr := io.ReadAll(rawReader)
		if rawErr != nil {
			return nil, fmt.Errorf("windsurf grpc: deflate frame: zlib: %v raw: %w", err, rawErr)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("windsurf grpc: unsupported compressed frame encoding %q", encoding)
	}
}

type windsurfGRPCClient struct {
	port      int
	csrfToken string
	client    *http.Client
}

var (
	windsurfGRPCClientsMu sync.Mutex
	windsurfGRPCClients   = map[int]*windsurfGRPCClient{}
)

func newWindsurfGRPCClient(port int, csrfToken string) *windsurfGRPCClient {
	windsurfGRPCClientsMu.Lock()
	defer windsurfGRPCClientsMu.Unlock()
	if client, ok := windsurfGRPCClients[port]; ok && client.csrfToken == csrfToken {
		return client
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &windsurfGRPCClient{
		port:      port,
		csrfToken: csrfToken,
		client:    &http.Client{Transport: transport},
	}
	windsurfGRPCClients[port] = client
	return client
}

func closeWindsurfGRPCClient(port int) {
	windsurfGRPCClientsMu.Lock()
	defer windsurfGRPCClientsMu.Unlock()
	if client, ok := windsurfGRPCClients[port]; ok {
		if transport, okTransport := client.client.Transport.(*http2.Transport); okTransport {
			transport.CloseIdleConnections()
		}
		delete(windsurfGRPCClients, port)
	}
}

func (c *windsurfGRPCClient) Unary(ctx context.Context, path string, payload []byte, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u := url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", c.port), Path: path}
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, u.String(), bytes.NewReader(windsurfGRPCFrame(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Grpc-Accept-Encoding", "identity,gzip,deflate")
	req.Header.Set("User-Agent", "grpc-go/1.0 cli-proxy-windsurf")
	req.Header.Set("x-codeium-csrf-token", c.csrfToken)

	resp, err := c.client.Do(req)
	if err != nil {
		closeWindsurfGRPCClient(c.port)
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		closeWindsurfGRPCClient(c.port)
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("windsurf grpc: HTTP %d: %s", resp.StatusCode, string(body))
	}
	if status := resp.Trailer.Get("Grpc-Status"); status != "" && status != "0" {
		msg := resp.Trailer.Get("Grpc-Message")
		if decoded, errUnescape := url.QueryUnescape(msg); errUnescape == nil {
			msg = decoded
		}
		if msg == "" {
			msg = "gRPC status " + status
		}
		return nil, fmt.Errorf("windsurf grpc: %s", msg)
	}
	encoding := resp.Header.Get("Grpc-Encoding")
	frames, err := windsurfExtractGRPCFramesWithEncoding(body, encoding)
	if err != nil {
		if stripped, stripErr := windsurfStripGRPCFrame(body, encoding); stripErr == nil {
			return stripped, nil
		}
		return nil, err
	}
	if len(frames) == 0 {
		return nil, nil
	}
	return bytes.Join(frames, nil), nil
}
