package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/client"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/pterm/pterm"

	localmcp "github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func scanLiveServer(ctx context.Context, serverCmd string) ([]model.UnifiedTool, error) {
	args := strings.Fields(serverCmd)
	if len(args) == 0 {
		return nil, fmt.Errorf("empty server command")
	}

	pterm.Printf("🔌 Connecting to live MCP server: %s...\n", serverCmd)

	c, err := client.NewStdioMCPClient(args[0], nil, args[1:]...)
	if err != nil {
		return nil, fmt.Errorf("failed to create stdio client: %w", err)
	}

	if startErr := c.Start(ctx); startErr != nil {
		return nil, fmt.Errorf("failed to start client: %w", startErr)
	}
	defer c.Close() //nolint:errcheck // closing client on exit, error is acceptable

	initReq := mcpgo.InitializeRequest{}
	initReq.Params.ProtocolVersion = "2024-11-05"
	initReq.Params.ClientInfo = mcpgo.Implementation{
		Name:    "tooltrust-scanner",
		Version: "1.0.0",
	}

	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	listReq := mcpgo.ListToolsRequest{}
	resp, err := c.ListTools(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("tools/list map failed: %w", err)
	}

	// We serialize the response back to JSON so we can use our existing adapter,
	// which also runs the inference rules for permissions.
	// Since mcp-go uses `mcpgo.Tool` and we expect `mcp.Tool`, we wrap it.
	type dummyResponse struct {
		Tools []mcpgo.Tool `json:"tools"`
	}
	payload := dummyResponse{Tools: resp.Tools}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tools: %w", err)
	}

	adapter := localmcp.NewAdapter()
	tools, err := adapter.Parse(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tools: %w", err)
	}
	return tools, nil
}
