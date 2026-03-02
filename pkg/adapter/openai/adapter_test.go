package openai_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/agentsentry/pkg/adapter/openai"
	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

func TestAdapter_Protocol(t *testing.T) {
	a := openai.NewAdapter()
	assert.Equal(t, model.ProtocolOpenAI, a.Protocol())
}

func TestAdapter_Parse_NotImplemented(t *testing.T) {
	t.Skip("OpenAI adapter not yet implemented")
	_, err := openai.NewAdapter().Parse(context.Background(), []byte("{}"))
	assert.NoError(t, err)
}
