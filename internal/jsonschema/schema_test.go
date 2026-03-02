package jsonschema_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/agentsentry/internal/jsonschema"
)

func TestSchema_PropertyNames(t *testing.T) {
	s := jsonschema.Schema{
		Type: "object",
		Properties: map[string]jsonschema.Property{
			"path":    {Type: "string"},
			"command": {Type: "string"},
		},
	}
	names := s.PropertyNames()
	assert.ElementsMatch(t, []string{"path", "command"}, names)
}

func TestSchema_HasProperty(t *testing.T) {
	s := jsonschema.Schema{
		Properties: map[string]jsonschema.Property{
			"url": {Type: "string"},
		},
	}
	assert.True(t, s.HasProperty("url"))
	assert.False(t, s.HasProperty("missing"))
}

func TestSchema_UnmarshalJSON(t *testing.T) {
	raw := `{"type":"object","properties":{"file":{"type":"string","description":"file path"},"content":{"type":"string"}},"required":["file"]}`
	var s jsonschema.Schema
	require.NoError(t, json.Unmarshal([]byte(raw), &s))
	assert.Equal(t, "object", s.Type)
	assert.True(t, s.HasProperty("file"))
	assert.True(t, s.HasProperty("content"))
	assert.Equal(t, []string{"file"}, s.Required)
	assert.Equal(t, "file path", s.Properties["file"].Description)
}

func TestSchema_Empty(t *testing.T) {
	var s jsonschema.Schema
	assert.Empty(t, s.PropertyNames())
	assert.False(t, s.HasProperty("anything"))
}
