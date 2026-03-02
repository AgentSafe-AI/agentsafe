// Package skills provides an Adapter for Markdown-based AI Skills format.
// This is a stub implementation — full parsing will be added in a future iteration.
package skills

import (
	"context"
	"fmt"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// Adapter converts Markdown-based Skill definitions into []model.UnifiedTool.
type Adapter struct{}

// NewAdapter returns a new Skills Adapter.
func NewAdapter() *Adapter { return &Adapter{} }

// Protocol implements adapter.Adapter.
func (a *Adapter) Protocol() model.ProtocolType { return model.ProtocolSkills }

// Parse implements adapter.Adapter.
// TODO: implement Markdown Skills format parsing (SKILL.md frontmatter + body).
func (a *Adapter) Parse(_ context.Context, _ []byte) ([]model.UnifiedTool, error) {
	return nil, fmt.Errorf("skills adapter: not yet implemented")
}
