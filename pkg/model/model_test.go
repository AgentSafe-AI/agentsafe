package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// --- UnifiedTool ---

func TestUnifiedTool_HasPermission(t *testing.T) {
	tool := model.UnifiedTool{
		Permissions: []model.Permission{model.PermissionFS, model.PermissionNetwork},
	}
	assert.True(t, tool.HasPermission(model.PermissionFS))
	assert.True(t, tool.HasPermission(model.PermissionNetwork))
	assert.False(t, tool.HasPermission(model.PermissionExec))
}

// --- RiskScore / Grade ---

func TestGradeFromScore(t *testing.T) {
	// Boundaries: A:0–9  B:10–24  C:25–49  D:50–74  F:75+
	// Source: ToolTrust Directory methodology v1.0
	cases := []struct {
		name  string
		score int
		want  model.Grade
	}{
		{"A lower", 0, model.GradeA},
		{"A upper", 9, model.GradeA},
		{"B lower", 10, model.GradeB},
		{"B upper", 24, model.GradeB},
		{"C lower", 25, model.GradeC},
		{"C upper", 49, model.GradeC},
		{"D lower", 50, model.GradeD},
		{"D upper", 74, model.GradeD},
		{"F lower", 75, model.GradeF},
		{"F large", 200, model.GradeF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := model.GradeFromScore(tc.score)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRiskScore_New(t *testing.T) {
	issues := []model.Issue{
		{Severity: model.SeverityHigh, Code: "TOOL_POISONING", Description: "injection detected", Location: "description"},
	}
	rs := model.NewRiskScore(30, issues)
	assert.Equal(t, 30, rs.Score)
	assert.Equal(t, model.GradeC, rs.Grade)
	assert.Len(t, rs.Issues, 1)
}

func TestRiskScore_IsClean(t *testing.T) {
	clean := model.NewRiskScore(0, nil)
	assert.True(t, clean.IsClean())

	dirty := model.NewRiskScore(5, []model.Issue{{Code: "X"}})
	assert.False(t, dirty.IsClean())
}

// --- GatewayPolicy / Action ---

func TestActionFromGrade(t *testing.T) {
	cases := []struct {
		grade model.Grade
		want  model.Action
	}{
		{model.GradeA, model.ActionAllow},
		{model.GradeB, model.ActionAllow},
		{model.GradeC, model.ActionRequireApproval},
		{model.GradeD, model.ActionRequireApproval},
		{model.GradeF, model.ActionBlock},
	}
	for _, tc := range cases {
		t.Run(string(tc.grade), func(t *testing.T) {
			got := model.ActionFromGrade(tc.grade)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNewGatewayPolicy(t *testing.T) {
	score := model.NewRiskScore(80, []model.Issue{{Code: "TOOL_POISONING", Severity: model.SeverityCritical}})
	policy := model.NewGatewayPolicy("dangerous_tool", score, nil)
	assert.Equal(t, "dangerous_tool", policy.ToolName)
	assert.Equal(t, model.ActionBlock, policy.Action)
	assert.Equal(t, score, policy.Score)
}
