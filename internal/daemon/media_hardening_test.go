package daemon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type syntheticTransport func(*http.Request) (*http.Response, error)

func (f syntheticTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type generatedBody struct {
	read   int64
	closed bool
}

func (b *generatedBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read += int64(len(p))
	return len(p), nil
}
func (b *generatedBody) Close() error { b.closed = true; return nil }

func TestMatrixDownloadsBoundBeforeUnboundedBuffering(t *testing.T) {
	const limit = 25 << 20
	for _, length := range []int64{limit + 1, -1} {
		b := &generatedBody{}
		cli, err := mautrix.NewClient("http://127.0.0.1:1", id.UserID("@synthetic:local"), "")
		if err != nil {
			t.Fatal(err)
		}
		cli.Client = &http.Client{Transport: syntheticTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: b, ContentLength: length, Request: r}, nil
		})}
		m := &Matrix{cli: cli}
		data, _, err := m.Download(context.Background(), "mxc://synthetic.local/media")
		if err == nil || data != nil || !b.closed || b.read > limit+1 {
			t.Fatalf("length=%d read=%d closed=%v err=%v", length, b.read, b.closed, err)
		}
		if length > limit && b.read != 0 {
			t.Fatal("declared oversized body should not be read")
		}
	}
}

func TestProviderMutationAndCaptureEntryPointsBlocked(t *testing.T) {
	m := &Matrix{} // nil provider proves refusal precedes provider or file access
	if _, err := m.SendText(context.Background(), "room", "txn", "text"); err == nil {
		t.Fatal("text send accepted")
	}
	if _, err := m.SendFile(context.Background(), "room", "txn", "/never-open", "caption"); err == nil {
		t.Fatal("file send accepted")
	}
	if err := m.MarkRead(context.Background(), "room", "event"); err == nil {
		t.Fatal("receipt accepted")
	}
	if _, err := NewMatrix(coldConfig(t), nil, nil); err == nil {
		t.Fatal("capture constructor accepted")
	}
	err := classify(errors.New("Authorization: Bearer *** password=SYNTHETIC_SECRET"))
	if strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
		t.Fatal("upstream credentials leaked")
	}
}

func TestSmallMatrixDownloadStillWorks(t *testing.T) {
	cli, err := mautrix.NewClient("http://127.0.0.1:1", id.UserID("@synthetic:local"), "")
	if err != nil {
		t.Fatal(err)
	}
	cli.Client = &http.Client{Transport: syntheticTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("synthetic attachment")), ContentLength: 20, Request: r}, nil
	})}
	b, _, err := (&Matrix{cli: cli}).Download(context.Background(), "mxc://synthetic.local/media")
	if err != nil || string(b) != "synthetic attachment" {
		t.Fatalf("download=%q err=%v", b, err)
	}
}
