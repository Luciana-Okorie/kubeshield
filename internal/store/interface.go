package store

import (
	"context"

	"github.com/luciana-okorie/kubeshield/internal/domain"
)

type Repository interface {
	ListFindings(context.Context, string, string, int) ([]domain.Finding, error)
	UpsertFinding(context.Context, domain.Finding) (bool, error)
	CompleteScan(context.Context, string, []string) (int64, error)
	UpdateFindingStatus(context.Context, string, string) (bool, error)
	Health(context.Context) error
}
