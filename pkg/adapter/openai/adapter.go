// Package openai provides an Adapter for the OpenAI Function Calling format.
// This is a stub implementation — full parsing will be added in a future iteration.
package openai

import (
	"context"
	"fmt"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// Adapter converts OpenAI function-calling tool definitions into []model.UnifiedTool.
type Adapter struct{}

// NewAdapter returns a new OpenAI Adapter.
func NewAdapter() *Adapter { return &Adapter{} }

// Protocol implements adapter.Adapter.
func (a *Adapter) Protocol() model.ProtocolType { return model.ProtocolOpenAI }

// Parse implements adapter.Adapter.
// TODO: implement OpenAI function-calling format parsing.
func (a *Adapter) Parse(_ context.Context, _ []byte) ([]model.UnifiedTool, error) {
	return nil, fmt.Errorf("openai adapter: not yet implemented")
}
