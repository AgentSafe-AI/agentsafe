package model

import (
	"encoding/json"

	"github.com/AgentSafe-AI/agentsentry/internal/jsonschema"
)

// ProtocolType identifies the source protocol of a tool.
type ProtocolType string

const (
	ProtocolMCP    ProtocolType = "mcp"
	ProtocolOpenAI ProtocolType = "openai"
	ProtocolSkills ProtocolType = "skills"
	ProtocolA2A    ProtocolType = "a2a"
)

// Permission represents a capability a tool may exercise.
type Permission string

const (
	PermissionExec    Permission = "exec"
	PermissionFS      Permission = "fs"
	PermissionNetwork Permission = "network"
	PermissionDB      Permission = "db"
	PermissionEnv     Permission = "env"
	PermissionHTTP    Permission = "http"
)

// UnifiedTool is the protocol-agnostic representation of any AI agent tool.
// All adapters normalise their wire format into this struct before analysis.
type UnifiedTool struct {
	ID          string
	Name        string
	Description string
	InputSchema jsonschema.Schema
	Permissions []Permission
	Protocol    ProtocolType
	RawSource   json.RawMessage
	Metadata    map[string]any
}

// HasPermission reports whether the tool holds the given permission.
func (t UnifiedTool) HasPermission(p Permission) bool {
	for _, perm := range t.Permissions {
		if perm == p {
			return true
		}
	}
	return false
}
