package main

import (
	"os"

	share "github.com/UniClipboard/unic-plugin-wormhole"
	"github.com/uniclipboard/unic/plugin"
)

func main() {
	if plugin.Serve(share.New(nil)) != nil {
		os.Exit(1)
	}
}
