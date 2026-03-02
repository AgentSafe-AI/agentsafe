// Package gateway derives enforcement policies from analyzer RiskScore values.
package gateway

import (
	"fmt"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// defaultGradeBRateLimit is applied to Grade-B tools that are allowed but should
// be monitored via rate limiting.
var defaultGradeBRateLimit = &model.RateLimit{
	RequestsPerMinute: 60,
	BurstSize:         10,
}

// Evaluate maps a RiskScore to a GatewayPolicy with a human-readable reason.
func Evaluate(toolName string, score model.RiskScore) (model.GatewayPolicy, error) {
	action := model.ActionFromGrade(score.Grade)
	reason := buildReason(action, score)

	var rateLimit *model.RateLimit
	if score.Grade == model.GradeB {
		rateLimit = defaultGradeBRateLimit
	}

	return model.GatewayPolicy{
		ToolName:  toolName,
		Action:    action,
		RateLimit: rateLimit,
		Reason:    reason,
		Score:     score,
	}, nil
}

func buildReason(action model.Action, score model.RiskScore) string {
	switch action {
	case model.ActionAllow:
		return fmt.Sprintf("risk score %d (grade %s): tool is within acceptable risk threshold", score.Score, score.Grade)
	case model.ActionRequireApproval:
		return fmt.Sprintf("risk score %d (grade %s): tool requires human approval before use", score.Score, score.Grade)
	case model.ActionBlock:
		return fmt.Sprintf("risk score %d (grade %s): tool exceeds risk threshold and must be blocked", score.Score, score.Grade)
	default:
		return fmt.Sprintf("risk score %d (grade %s)", score.Score, score.Grade)
	}
}
