package gateway_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/agentsentry/pkg/gateway"
	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

func TestEvaluate_GradeA_Allow(t *testing.T) {
	score := model.NewRiskScore(5, nil)
	policy, err := gateway.Evaluate("safe_tool", score)
	require.NoError(t, err)
	assert.Equal(t, model.ActionAllow, policy.Action)
	assert.Equal(t, "safe_tool", policy.ToolName)
}

func TestEvaluate_GradeB_Allow(t *testing.T) {
	score := model.NewRiskScore(20, []model.Issue{{Code: "LOW_RISK", Severity: model.SeverityLow}})
	policy, err := gateway.Evaluate("tool_b", score)
	require.NoError(t, err)
	assert.Equal(t, model.ActionAllow, policy.Action)
}

func TestEvaluate_GradeC_RequireApproval(t *testing.T) {
	score := model.NewRiskScore(30, []model.Issue{{Code: "X", Severity: model.SeverityMedium}})
	policy, err := gateway.Evaluate("risky_tool", score)
	require.NoError(t, err)
	assert.Equal(t, model.ActionRequireApproval, policy.Action)
}

func TestEvaluate_GradeD_RequireApproval(t *testing.T) {
	score := model.NewRiskScore(60, []model.Issue{{Code: "Y", Severity: model.SeverityHigh}})
	policy, err := gateway.Evaluate("high_risk", score)
	require.NoError(t, err)
	assert.Equal(t, model.ActionRequireApproval, policy.Action)
}

func TestEvaluate_GradeF_Block(t *testing.T) {
	score := model.NewRiskScore(100, []model.Issue{{Code: "TOOL_POISONING", Severity: model.SeverityCritical}})
	policy, err := gateway.Evaluate("evil_tool", score)
	require.NoError(t, err)
	assert.Equal(t, model.ActionBlock, policy.Action)
}

func TestEvaluate_ReasonNotEmpty(t *testing.T) {
	score := model.NewRiskScore(100, []model.Issue{{Code: "TOOL_POISONING", Severity: model.SeverityCritical}})
	policy, err := gateway.Evaluate("evil_tool", score)
	require.NoError(t, err)
	assert.NotEmpty(t, policy.Reason)
}

func TestEvaluate_RateLimitAppliedForGradeB(t *testing.T) {
	score := model.NewRiskScore(15, []model.Issue{{Code: "X", Severity: model.SeverityLow}})
	policy, err := gateway.Evaluate("monitored_tool", score)
	require.NoError(t, err)
	assert.Equal(t, model.ActionAllow, policy.Action)
	// Grade B tools should have a default rate limit applied
	assert.NotNil(t, policy.RateLimit)
	assert.Greater(t, policy.RateLimit.RequestsPerMinute, 0)
}

func TestEvaluate_NoRateLimitForGradeA(t *testing.T) {
	score := model.NewRiskScore(0, nil)
	policy, err := gateway.Evaluate("clean_tool", score)
	require.NoError(t, err)
	assert.Nil(t, policy.RateLimit)
}

func TestEvaluate_ScoreEmbedded(t *testing.T) {
	score := model.NewRiskScore(55, []model.Issue{{Code: "Z", Severity: model.SeverityHigh}})
	policy, err := gateway.Evaluate("tool", score)
	require.NoError(t, err)
	assert.Equal(t, score, policy.Score)
}
