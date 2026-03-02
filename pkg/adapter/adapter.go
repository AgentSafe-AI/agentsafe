// Package adapter defines the protocol-agnostic Adapter interface and the
// registry used to select the correct adapter at runtime.
package adapter

import (
	"context"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// Adapter converts a protocol-specific tool list payload into a slice of
// UnifiedTool values that the analyzer can process.
type Adapter interface {
	// Parse accepts the raw bytes of a tool-list response (e.g. MCP
	// tools/list JSON) and returns the normalised tool representations.
	Parse(ctx context.Context, data []byte) ([]model.UnifiedTool, error)

	// Protocol returns the ProtocolType this adapter handles.
	Protocol() model.ProtocolType
}
