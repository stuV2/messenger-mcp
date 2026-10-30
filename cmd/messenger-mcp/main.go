// Command messenger-mcp runs the stuV2 capture-disabled Messenger MCP fork.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xjesus/messenger-mcp/internal/daemon"
)

const usage = `Usage:
  messenger-mcp serve [--data DIR]    Start authenticated local read-only MCP
  messenger-mcp pair-url             Refused: pairing and capture are disabled
  messenger-mcp version

Fork: stuV2/messenger-mcp. This release does not connect a private account.
Only MCP_TOKEN is required in the private secrets.env file. Source capture,
pairing and sends remain blocked pending a separate privacy decision.`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", daemon.DefaultDataDir(), "private data directory")
	_ = fs.Parse(os.Args[2:])
	if fs.NArg() != 0 {
		fail(fmt.Errorf("unexpected positional arguments"))
	}
	switch cmd {
	case "serve":
		cfg, err := daemon.LoadConfig(*data)
		if err != nil {
			fail(err)
		}
		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := daemon.Run(ctx, cfg, log); err != nil {
			fail(err)
		}
	case "pair-url":
		fail(fmt.Errorf("pairing and source capture are disabled pending separate privacy approval; no provider contacted"))
	case "version":
		fmt.Println(daemon.Identity + " " + daemon.Version)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

func fail(err error) { fmt.Fprintln(os.Stderr, "messenger-mcp:", err); os.Exit(1) }
