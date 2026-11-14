package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/luciana-okorie/kubeshield/internal/domain"
)

type Postgres struct{ pool *pgxpool.Pool }

func NewPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}
func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) ListFindings(ctx context.Context, clusterID, status string, limit int) ([]domain.Finding, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `
		SELECT id::text, cluster_id, namespace, resource, resource_name, category,
		severity, title, description, remediation, fingerprint, detected_at, status
		FROM findings
		WHERE ($1 = '' OR cluster_id = $1) AND ($2 = '' OR status = $2)
		ORDER BY detected_at DESC LIMIT $3`, clusterID, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Finding
	for rows.Next() {
		var f domain.Finding
		if err := rows.Scan(&f.ID, &f.ClusterID, &f.Namespace, &f.Resource, &f.ResourceName,
			&f.Category, &f.Severity, &f.Title, &f.Description, &f.Remediation,
			&f.Fingerprint, &f.DetectedAt, &f.Status); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (p *Postgres) UpsertFinding(ctx context.Context, f domain.Finding) (bool, error) {
	tag, err := p.pool.Exec(ctx, `
		INSERT INTO findings (
			cluster_id,
			namespace,
			resource,
			resource_name,
			category,
			severity,
			title,
			description,
			remediation,
			fingerprint,
			detected_at,
			status
		)
		VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),'open'
		)
		ON CONFLICT (fingerprint)
		DO UPDATE SET
			severity = EXCLUDED.severity,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			remediation = EXCLUDED.remediation,
			detected_at = NOW(),
			status = 'open'
		WHERE
			findings.severity IS DISTINCT FROM EXCLUDED.severity
			OR findings.title IS DISTINCT FROM EXCLUDED.title
			OR findings.description IS DISTINCT FROM EXCLUDED.description
			OR findings.remediation IS DISTINCT FROM EXCLUDED.remediation
			OR findings.status <> 'open'`,
		f.ClusterID,
		f.Namespace,
		f.Resource,
		f.ResourceName,
		f.Category,
		f.Severity,
		f.Title,
		f.Description,
		f.Remediation,
		f.Fingerprint,
	)

	if err != nil {
		return false, err
	}

	return tag.RowsAffected() > 0, nil
}

// CompleteScan resolves active findings for a cluster that were not present in
// the latest successful scan. A failed scan must never call this method.
func (p *Postgres) CompleteScan(ctx context.Context, clusterID string, fingerprints []string) (int64, error) {
	tag, err := p.pool.Exec(ctx, `
		UPDATE findings
		SET status = 'resolved'
		WHERE cluster_id = $1
		  AND status <> 'resolved'
		  AND NOT (fingerprint = ANY($2::text[]))`, clusterID, fingerprints)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) Health(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return fmt.Errorf("database ping: %w", err)
	}
	return nil
}

func (p *Postgres) UpdateFindingStatus(
	ctx context.Context,
	findingID string,
	status string,
) (bool, error) {

	if status != "open" && status != "acknowledged" && status != "resolved" {
		return false, fmt.Errorf("invalid finding status: %s", status)
	}

	tag, err := p.pool.Exec(ctx, `
        UPDATE findings
        SET status = $1
        WHERE id = $2
    `, status, findingID)

	if err != nil {
		return false, err
	}

	return tag.RowsAffected() > 0, nil
}
