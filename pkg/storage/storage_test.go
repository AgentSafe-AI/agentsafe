package storage_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
	"github.com/AgentSafe-AI/agentsentry/pkg/storage"
)

func openTestStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleRecord(id string) storage.ScanRecord {
	return storage.ScanRecord{
		ID:        id,
		ToolName:  "run_shell",
		Protocol:  model.ProtocolMCP,
		RiskScore: 55,
		Grade:     model.GradeD,
		Findings: []model.Issue{
			{RuleID: "AS-001", Severity: model.SeverityCritical, Code: "TOOL_POISONING", Description: "prompt injection", Location: "description"},
			{RuleID: "AS-002", Severity: model.SeverityHigh, Code: "HIGH_RISK_PERMISSION", Description: "exec permission", Location: "permissions"},
		},
		ScannedAt: time.Now().UTC().Truncate(time.Second),
	}
}

func TestStore_Open_InMemory(t *testing.T) {
	s := openTestStore(t)
	assert.NotNil(t, s)
}

func TestStore_Save_And_Get(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	rec := sampleRecord("test-001")

	require.NoError(t, s.Save(ctx, rec))

	got, err := s.Get(ctx, "test-001")
	require.NoError(t, err)

	assert.Equal(t, rec.ID, got.ID)
	assert.Equal(t, rec.ToolName, got.ToolName)
	assert.Equal(t, rec.Protocol, got.Protocol)
	assert.Equal(t, rec.RiskScore, got.RiskScore)
	assert.Equal(t, rec.Grade, got.Grade)
	assert.Len(t, got.Findings, 2)
	assert.Equal(t, "AS-001", got.Findings[0].RuleID)
}

func TestStore_Get_NotFound(t *testing.T) {
	s := openTestStore(t)
	_, err := s.Get(context.Background(), "does-not-exist")
	require.Error(t, err)
	assert.ErrorIs(t, err, sql.ErrNoRows, "Get for missing ID must wrap sql.ErrNoRows")
}

func TestStore_Save_Replace(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := sampleRecord("dup-001")
	require.NoError(t, s.Save(ctx, rec))

	rec.RiskScore = 80
	rec.Grade = model.GradeF
	require.NoError(t, s.Save(ctx, rec))

	got, err := s.Get(ctx, "dup-001")
	require.NoError(t, err)
	assert.Equal(t, 80, got.RiskScore)
	assert.Equal(t, model.GradeF, got.Grade)
}

func TestStore_Count(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	n, err := s.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	require.NoError(t, s.Save(ctx, sampleRecord("a")))
	require.NoError(t, s.Save(ctx, sampleRecord("b")))

	n, err = s.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestStore_ListByGrade(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	recD := sampleRecord("grade-d-001")
	recF := sampleRecord("grade-f-001")
	recF.Grade = model.GradeF
	recF.RiskScore = 80

	require.NoError(t, s.Save(ctx, recD))
	require.NoError(t, s.Save(ctx, recF))

	ds, err := s.ListByGrade(ctx, model.GradeD)
	require.NoError(t, err)
	assert.Len(t, ds, 1)
	assert.Equal(t, "grade-d-001", ds[0].ID)

	fs, err := s.ListByGrade(ctx, model.GradeF)
	require.NoError(t, err)
	assert.Len(t, fs, 1)

	as, err := s.ListByGrade(ctx, model.GradeA)
	require.NoError(t, err)
	assert.Empty(t, as)
}

func TestStore_Findings_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	rec := sampleRecord("findings-rt")
	rec.Findings = []model.Issue{
		{RuleID: "AS-004", Severity: model.SeverityHigh, Code: "CVE", Description: "CVE-2024-1234 in lodash", Location: "dependencies"},
	}
	require.NoError(t, s.Save(ctx, rec))

	got, err := s.Get(ctx, "findings-rt")
	require.NoError(t, err)
	require.Len(t, got.Findings, 1)
	assert.Equal(t, "AS-004", got.Findings[0].RuleID)
	assert.Equal(t, "CVE-2024-1234 in lodash", got.Findings[0].Description)
}
