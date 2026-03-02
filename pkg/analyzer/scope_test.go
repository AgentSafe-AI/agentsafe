package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/agentsentry/pkg/analyzer"
	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

func TestScopeChecker_NoMismatch(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "read_file",
		Description: "Read a file from disk.",
		Permissions: []model.Permission{model.PermissionFS},
	}
	issues, err := analyzer.NewScopeChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestScopeChecker_ReadNameWithExec(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "get_weather",
		Description: "Get current weather data.",
		Permissions: []model.Permission{model.PermissionExec},
	}
	issues, err := analyzer.NewScopeChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "SCOPE_MISMATCH", issues[0].Code)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity)
}

func TestScopeChecker_ReadPrefixWithNetwork(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "read_config",
		Description: "Read configuration.",
		Permissions: []model.Permission{model.PermissionNetwork},
	}
	issues, err := analyzer.NewScopeChecker().Check(tool)
	require.NoError(t, err)
	assert.NotEmpty(t, issues)
}

func TestScopeChecker_ListPrefixWithDB(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "list_users",
		Description: "List all registered users.",
		Permissions: []model.Permission{model.PermissionDB},
	}
	// list_users with DB is expected — no mismatch
	issues, err := analyzer.NewScopeChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestScopeChecker_WriteNameWithNoWritePermission(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "write_log",
		Description: "Write log entries.",
		Permissions: []model.Permission{model.PermissionNetwork},
	}
	issues, err := analyzer.NewScopeChecker().Check(tool)
	require.NoError(t, err)
	assert.NotEmpty(t, issues)
}
