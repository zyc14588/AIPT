package main

import (
	"fmt"
	"os"

	"github.com/zyc14588/AIPT/internal/pilot"
)

// Build bindings are externally accepted values, never CLI/request options.
// An unbound build fails closed and cannot start an inference process.
var acceptedRuntimeManifestSHA string
var acceptedEntryMode string
var acceptedParentBindingSHA string
var acceptedPreparationBindingSHA string
var acceptedSetupBindingSHA string

func main() {
	if acceptedEntryMode == "TASK0_SETUP" {
		if err := pilot.RunAcceptedTask0Setup(acceptedSetupBindingSHA); err != nil {
			fmt.Fprintln(os.Stderr, "B007 accepted setup did not complete")
			os.Exit(1)
		}
		return
	}
	if acceptedEntryMode == "TASK0_PARENT" {
		if err := pilot.RunAcceptedTask0Parent(acceptedParentBindingSHA); err != nil {
			fmt.Fprintln(os.Stderr, "B007 accepted parent launch did not complete")
			pilot.WaitAcceptedTask0InputRetirements()
			os.Exit(1)
		}
		return
	}
	if acceptedEntryMode == "TASK0_PREP" {
		if err := pilot.RunAcceptedTask0Preparation(acceptedPreparationBindingSHA); err != nil {
			fmt.Fprintln(os.Stderr, "B007 accepted preparation did not complete")
			pilot.WaitAcceptedTask0InputRetirements()
			os.Exit(1)
		}
		return
	}
	if acceptedEntryMode == "TASK0_REMOTE" {
		if err := pilot.RunFrozenTask0Remote(acceptedRuntimeManifestSHA); err != nil {
			fmt.Fprintln(os.Stderr, "B007 remote capsule did not pass its launch gates")
			os.Exit(1)
		}
		return
	}
	if acceptedEntryMode == "TASK0_GAME" {
		if err := pilot.RunFrozenTask0Game(acceptedRuntimeManifestSHA); err != nil {
			fmt.Fprintln(os.Stderr, "B007 game capsule did not pass its launch gates")
			os.Exit(1)
		}
		return
	}
	if acceptedEntryMode != "" && acceptedEntryMode != "LOCAL_RUNTIME" {
		fmt.Fprintln(os.Stderr, "B007 accepted entry binding required")
		os.Exit(1)
	}
	if os.Getenv("AIPT_RUNTIME_ISOLATOR") != "1" || len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "B007 accepted private launch binding required")
		os.Exit(1)
	}
	if err := pilot.RunFrozenRuntimeIsolator(acceptedRuntimeManifestSHA); err != nil {
		fmt.Fprintln(os.Stderr, "B007 frozen runtime did not pass its launch gates")
		os.Exit(1)
	}
}
