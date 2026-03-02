// Package sandbox defines the interface for executing tools in an isolated
// environment. The implementation is reserved for a future K8s + gVisor
// integration; only the interface contract is established here.
package sandbox

import (
	"context"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// ExecutionResult holds the output of a sandboxed tool invocation.
type ExecutionResult struct {
	Stdout     string
	Stderr     string
	ExitCode   int
	Syscalls   []string // captured system calls (requires gVisor seccomp tracing)
	FileWrites []string // file paths written during execution
	NetConns   []string // outbound network connections observed
}

// Sandbox describes a controlled execution environment for dynamic tool analysis.
// Implementations are expected to use K8s Jobs with gVisor (runsc) runtime.
type Sandbox interface {
	// Execute runs the given tool with the provided arguments inside the sandbox
	// and returns an observation of its runtime behaviour.
	Execute(ctx context.Context, tool model.UnifiedTool, args map[string]any) (ExecutionResult, error)

	// Available reports whether the sandbox backend is reachable and ready.
	Available(ctx context.Context) bool
}
