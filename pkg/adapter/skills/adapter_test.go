package skills_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/agentsentry/pkg/adapter/skills"
	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

func TestAdapter_Protocol(t *testing.T) {
	a := skills.NewAdapter()
	assert.Equal(t, model.ProtocolSkills, a.Protocol())
}

func TestAdapter_Parse_NotImplemented(t *testing.T) {
	t.Skip("Skills adapter not yet implemented")
	_, err := skills.NewAdapter().Parse(context.Background(), []byte(""))
	assert.NoError(t, err)
}
