package main

import (
	"os"

	"github.com/zyc14588/AIPT/internal/modelgateway"
)

func main() {
	if err := modelgateway.RunRuntimeIsolator(); err != nil {
		os.Exit(1)
	}
}
