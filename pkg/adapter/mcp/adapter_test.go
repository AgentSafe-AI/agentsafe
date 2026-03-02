package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/agentsentry/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

func TestAdapter_Protocol(t *testing.T) {
	a := mcp.NewAdapter()
	assert.Equal(t, model.ProtocolMCP, a.Protocol())
}

func TestAdapter_Parse_BasicTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "read_file",
				Description: "Read the contents of a file from the filesystem",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"path": {Type: "string", Description: "absolute file path"},
					},
					Required: []string{"path"},
				},
			},
		},
	})

	a := mcp.NewAdapter()
	tools, err := a.Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	tool := tools[0]
	assert.Equal(t, "read_file", tool.Name)
	assert.Equal(t, model.ProtocolMCP, tool.Protocol)
	assert.True(t, tool.InputSchema.HasProperty("path"))
	assert.Contains(t, tool.Permissions, model.PermissionFS)
}

func TestAdapter_Parse_NetworkTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "fetch_url",
				Description: "Fetch content from a remote URL over the network",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"url": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Contains(t, tools[0].Permissions, model.PermissionNetwork)
}

func TestAdapter_Parse_ExecTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "run_command",
				Description: "Execute a shell command",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"command": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Contains(t, tools[0].Permissions, model.PermissionExec)
}

func TestAdapter_Parse_MultipleTools(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{Name: "tool_a", Description: "first tool"},
			{Name: "tool_b", Description: "second tool"},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Len(t, tools, 2)
}

func TestAdapter_Parse_EmptyList(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{Tools: []mcp.Tool{}})
	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Empty(t, tools)
}

func TestAdapter_Parse_InvalidJSON(t *testing.T) {
	_, err := mcp.NewAdapter().Parse(context.Background(), []byte("not json"))
	assert.Error(t, err)
}

func TestAdapter_Parse_PreservesRawSource(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{Name: "some_tool", Description: "desc"},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.NotEmpty(t, tools[0].RawSource)
}

func TestAdapter_Parse_DBTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "query_db",
				Description: "Run a SQL query against the database",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"query": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Contains(t, tools[0].Permissions, model.PermissionDB)
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
