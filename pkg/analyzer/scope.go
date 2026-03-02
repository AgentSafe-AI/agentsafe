package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// readOnlyPrefixes are name prefixes that imply the tool only reads data.
var readOnlyPrefixes = []string{"get_", "read_", "fetch_", "list_", "search_", "find_", "show_", "describe_"}

// writePermissions are permissions that imply mutating / side-effect operations.
var writePermissions = []model.Permission{
	model.PermissionExec,
	model.PermissionNetwork,
}

// ScopeChecker detects mismatches between a tool's name semantics and its
// declared permissions.
type ScopeChecker struct{}

// NewScopeChecker returns a new ScopeChecker.
func NewScopeChecker() *ScopeChecker { return &ScopeChecker{} }

// Check raises SCOPE_MISMATCH issues when a "read-only" named tool holds
// write-class permissions, or when a "write" named tool lacks write permissions.
func (c *ScopeChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	nameLower := strings.ToLower(tool.Name)
	var issues []model.Issue

	isReadOnlyName := false
	for _, prefix := range readOnlyPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			isReadOnlyName = true
			break
		}
	}

	if isReadOnlyName {
		for _, perm := range tool.Permissions {
			for _, wp := range writePermissions {
				if perm == wp {
					issues = append(issues, model.Issue{
						RuleID:   "AS-003",
						Severity: model.SeverityHigh,
						Code:     "SCOPE_MISMATCH",
						Description: fmt.Sprintf(
							"tool name %q implies read-only operation but declares %s permission",
							tool.Name, perm,
						),
						Location: "name+permissions",
					})
				}
			}
		}
	}

	// write-prefixed names should have at least one write permission
	writePrefixes := []string{"write_", "update_", "delete_", "remove_", "create_", "set_"}
	isWriteName := false
	for _, prefix := range writePrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			isWriteName = true
			break
		}
	}

	// write_*/update_*/create_*/delete_* names typically imply FS or DB access.
	// If they only carry network/exec permissions with no FS/DB, that is suspicious.
	writeLocalPerms := []model.Permission{model.PermissionFS, model.PermissionDB, model.PermissionExec}
	if isWriteName && len(tool.Permissions) > 0 {
		hasLocalWritePerm := false
		for _, perm := range tool.Permissions {
			for _, lp := range writeLocalPerms {
				if perm == lp {
					hasLocalWritePerm = true
				}
			}
		}
		if !hasLocalWritePerm {
			issues = append(issues, model.Issue{
				RuleID:      "AS-003",
				Severity:    model.SeverityMedium,
				Code:        "SCOPE_MISMATCH",
				Description: fmt.Sprintf("tool name %q implies local write operation but only remote/network-class permissions were detected", tool.Name),
				Location:    "name+permissions",
			})
		}
	}

	return issues, nil
}
