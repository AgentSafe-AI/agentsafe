// Package main provides the AgentSafe MCP Server — the meta-scanner.
// It exposes AgentSafe's scanning capability as an MCP tool so that any
// AI agent can call it to self-inspect other tool definitions.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/AgentSafe-AI/agentsentry/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/agentsentry/pkg/analyzer"
	"github.com/AgentSafe-AI/agentsentry/pkg/gateway"
	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	srv := server.NewMCPServer(
		"agentsentry",
		version,
	)

	srv.AddTool(buildScanTool(), handleScan)

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintf(os.Stderr, "agentsentry mcp server error: %v\n", err)
		os.Exit(1)
	}
}

// buildScanTool defines the MCP tool schema for the scan capability.
func buildScanTool() mcplib.Tool {
	return mcplib.NewTool(
		"agentsentry_scan",
		mcplib.WithDescription(
			"Scan a list of AI agent tool definitions for security risks. "+
				"Accepts an MCP tools/list JSON payload and returns a risk report "+
				"with gateway policies (ALLOW, REQUIRE_APPROVAL, or BLOCK) for each tool.",
		),
		mcplib.WithString(
			"tools_json",
			mcplib.Required(),
			mcplib.Description(`JSON string containing an MCP tools/list response, e.g. {"tools":[{"name":"...","description":"...","inputSchema":{...}}]}`),
		),
		mcplib.WithString(
			"protocol",
			mcplib.Description("Protocol format of the tool list. Currently supported: mcp (default)."),
		),
	)
}

// ScanResult is the JSON shape returned by the agentsentry_scan tool.
type ScanResult struct {
	Policies []model.GatewayPolicy `json:"policies"`
	Summary  ScanSummary           `json:"summary"`
}

// ScanSummary gives a high-level count of the enforcement decisions.
type ScanSummary struct {
	Total    int `json:"total"`
	Allowed  int `json:"allowed"`
	Approval int `json:"requireApproval"`
	Blocked  int `json:"blocked"`
}

// handleScan is the ToolHandlerFunc for the agentsentry_scan MCP tool.
func handleScan(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	toolsJSON, ok := req.GetArguments()["tools_json"].(string)
	if !ok || toolsJSON == "" {
		return mcplib.NewToolResultError("tools_json argument is required and must be a non-empty string"), nil
	}

	protocol := "mcp"
	if p, ok := req.GetArguments()["protocol"].(string); ok && p != "" {
		protocol = p
	}

	var tools []model.UnifiedTool
	var parseErr error

	switch protocol {
	case "mcp":
		a := mcp.NewAdapter()
		tools, parseErr = a.Parse(ctx, []byte(toolsJSON))
	default:
		return mcplib.NewToolResultError(fmt.Sprintf("unsupported protocol %q — supported: mcp", protocol)), nil
	}

	if parseErr != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to parse tool definitions: %v", parseErr)), nil
	}

	scanner := analyzer.NewScanner()
	var policies []model.GatewayPolicy
	summary := ScanSummary{Total: len(tools)}

	for i := range tools {
		score, scanErr := scanner.Scan(ctx, tools[i])
		if scanErr != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("scan failed for tool %q: %v", tools[i].Name, scanErr)), nil
		}
		policy, evalErr := gateway.Evaluate(tools[i].Name, score)
		if evalErr != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("policy evaluation failed for tool %q: %v", tools[i].Name, evalErr)), nil
		}
		policies = append(policies, policy)

		switch policy.Action {
		case model.ActionAllow:
			summary.Allowed++
		case model.ActionRequireApproval:
			summary.Approval++
		case model.ActionBlock:
			summary.Blocked++
		}
	}

	result := ScanResult{Policies: policies, Summary: summary}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to serialize result: %v", err)), nil
	}

	return mcplib.NewToolResultText(string(encoded)), nil
}
