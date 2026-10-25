// Command passkeyd runs the WebAuthn relying-party server, the offline demo
// and the inspect tool. See "passkeyd help".
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/SlateGitOrg/passkeyd/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
