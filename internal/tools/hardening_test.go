package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xjesus/messenger-mcp/internal/ledger"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func TestProductionRegistrationAlwaysColdAndMetadataOnly(t *testing.T) {
	_, l, reads, _ := setup(t)
	ctx := context.Background()
	for i := 0; i < 105; i++ {
		id := fmt.Sprintf("fixture-%03d", i)
		if err := l.UpsertChat(ctx, ledger.Chat{ChatID: id, RoomID: "!" + id + ":synthetic", Name: id}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := l.InsertMessage(ctx, ledger.Message{EventID: "$" + id, ChatID: id, TS: 1, Text: "BODY_MUST_NOT_ESCAPE", MediaName: "PRIVATE_ATTACHMENT_NAME"}); err != nil {
			t.Fatal(err)
		}
	}
	s := server.NewMCPServer("cold", "test", server.WithToolCapabilities(true))
	// Even accidental legacy flags cannot expand production registration.
	Register(s, Deps{L: l, Reads: reads, BodyAccessEnabled: true, WritesEnabled: true})
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(rpc(t, s, "tools/list", map[string]any{}), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 2 {
		t.Fatalf("tools=%+v", list.Tools)
	}
	for _, tool := range list.Tools {
		if tool.Name != "get_status" && tool.Name != "list_chats" {
			t.Fatal(tool.Name)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		res, text := call(t, s, "list_chats", map[string]any{"limit": 30, "after_chat_id": cursor})
		if res.IsError {
			t.Fatal(text)
		}
		for _, forbidden := range []string{"BODY_MUST_NOT_ESCAPE", "PRIVATE_ATTACHMENT_NAME", "last_message", "media_mxc", "Le echo un vistazo"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("metadata leaked %s", forbidden)
			}
		}
		var out struct {
			Chats []ledger.ChatMetadata `json:"chats"`
			More  bool                  `json:"has_more"`
			Next  string                `json:"next_chat_id"`
		}
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Chats) > 30 {
			t.Fatal("page cap")
		}
		for _, c := range out.Chats {
			if seen[c.ChatID] {
				t.Fatalf("duplicate chat %s", c.ChatID)
			}
			seen[c.ChatID] = true
		}
		if !out.More {
			if out.Next != "" {
				t.Fatal("terminal cursor must be empty")
			}
			break
		}
		if out.Next == "" || out.Next == cursor {
			t.Fatal("non-progressing cursor")
		}
		cursor = out.Next
	}
	if len(seen) != 106 {
		t.Fatalf("enumerated %d metadata rows, want 106", len(seen))
	}
	// Missing registration must deny direct tools/call, not merely hide in list.
	for _, name := range []string{"send_message", "send_file", "mark_read", "cancel_outbox", "get_messages", "search_messages", "history_since", "get_message_context", "download_attachment"} {
		req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": map[string]any{"chat_id": "245962885415945", "text": "must not queue"}}})
		b, _ := json.Marshal(s.HandleMessage(ctx, req))
		var response struct {
			Error  any                 `json:"error"`
			Result *mcp.CallToolResult `json:"result"`
		}
		if err := json.Unmarshal(b, &response); err != nil {
			t.Fatal(err)
		}
		if response.Error == nil && (response.Result == nil || !response.Result.IsError) {
			t.Fatalf("direct %s succeeded: %s", name, b)
		}
	}
	if reads.event != "" {
		t.Fatal("receipt sent")
	}
}

func TestLegacyExecutionGatesDenyBeforeDependencies(t *testing.T) {
	s := server.NewMCPServer("legacy-guard", "test", server.WithToolCapabilities(true))
	// Nil dependencies prove denial is before ledger, queue or provider access.
	registerRead(s, Deps{})
	registerSend(s, Deps{})
	for _, name := range []string{"send_message", "send_file", "mark_read", "cancel_outbox", "get_messages", "search_messages", "history_since", "get_message_context", "download_attachment"} {
		res, text := call(t, s, name, map[string]any{"chat_id": "synthetic", "message_id": "$synthetic", "job_id": "synthetic", "query": "body", "text": "body", "path": "/not-opened"})
		if !res.IsError || !strings.Contains(text, "disabled") {
			t.Fatalf("execution guard %s failed: %s", name, text)
		}
	}
	res, err := download(context.Background(), Deps{}, "$synthetic")
	if err != nil || !res.IsError {
		t.Fatal("direct download not gated")
	}
}
