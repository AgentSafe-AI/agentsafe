package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/agentsentry/internal/jsonschema"
	"github.com/AgentSafe-AI/agentsentry/pkg/analyzer"
	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

func TestPermissionChecker_NoPermissions(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "greet",
		Description: "Say hello to the user.",
		Permissions: nil,
	}
	checker := analyzer.NewPermissionChecker()
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestPermissionChecker_ExecPermission_HighRisk(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "run_script",
		Description: "Runs an arbitrary script.",
		Permissions: []model.Permission{model.PermissionExec},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "HIGH_RISK_PERMISSION", issues[0].Code)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity)
}

func TestPermissionChecker_DBPermission_MediumRisk(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "query",
		Permissions: []model.Permission{model.PermissionDB},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, model.SeverityMedium, issues[0].Severity)
}

func TestPermissionChecker_MultipleHighRisk(t *testing.T) {
	tool := model.UnifiedTool{
		Permissions: []model.Permission{model.PermissionExec, model.PermissionNetwork},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	assert.Len(t, issues, 2)
}

func TestPermissionChecker_SchemaPropCountNote(t *testing.T) {
	props := make(map[string]jsonschema.Property)
	for i := range 15 {
		props[string(rune('a'+i))] = jsonschema.Property{Type: "string"}
	}
	tool := model.UnifiedTool{
		InputSchema: jsonschema.Schema{Properties: props},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	var found bool
	for _, iss := range issues {
		if iss.Code == "LARGE_INPUT_SURFACE" {
			found = true
		}
	}
	assert.True(t, found, "expected LARGE_INPUT_SURFACE issue for schemas with >10 properties")
}
