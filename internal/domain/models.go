package domain

import "time"

type Cluster struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Context   string    `json:"context"`
	CreatedAt time.Time `json:"created_at"`
}

type Finding struct {
	ID           string    `json:"id"`
	ClusterID    string    `json:"cluster_id"`
	Namespace    string    `json:"namespace"`
	Resource     string    `json:"resource"`
	ResourceName string    `json:"resource_name"`
	Category     string    `json:"category"`
	Severity     string    `json:"severity"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Remediation  string    `json:"remediation"`
	Fingerprint  string    `json:"fingerprint"`
	DetectedAt   time.Time `json:"detected_at"`
	Status       string    `json:"status"`
}

type Incident struct {
	ID          string    `json:"id"`
	ClusterID   string    `json:"cluster_id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ScanSummary struct {
	ClusterID       string    `json:"cluster_id"`
	Nodes           int       `json:"nodes"`
	Pods            int       `json:"pods"`
	UnhealthyPods   int       `json:"unhealthy_pods"`
	RestartingPods  int       `json:"restarting_pods"`
	FindingsCreated int       `json:"findings_created"`
	ScannedAt       time.Time `json:"scanned_at"`
}

type WorkloadSnapshot struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Ready     int32  `json:"ready"`
	Desired   int32  `json:"desired"`
	Available int32  `json:"available"`
}
