package main

import (
	"os"

	"github.com/cicdecoy/cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
