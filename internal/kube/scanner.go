package kube

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/luciana-okorie/kubeshield/internal/domain"
)

type Scanner interface {
	Scan(context.Context, string) ([]domain.Finding, domain.ScanSummary, error)
}

type KubernetesScanner struct{ client kubernetes.Interface }

func NewScanner(kubeconfig string) (*KubernetesScanner, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		loadingRules.ExplicitPath = kubeconfig
	} else if home, err := os.UserHomeDir(); err == nil {
		loadingRules.ExplicitPath = filepath.Join(home, ".kube", "config")
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil && kubeconfig == "" {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &KubernetesScanner{client: client}, nil
}

func (s *KubernetesScanner) Scan(ctx context.Context, clusterID string) ([]domain.Finding, domain.ScanSummary, error) {
	now := time.Now().UTC()
	summary := domain.ScanSummary{ClusterID: clusterID, ScannedAt: now}
	nodes, err := s.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, summary, fmt.Errorf("list nodes: %w", err)
	}
	summary.Nodes = len(nodes.Items)
	pods, err := s.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, summary, fmt.Errorf("list pods: %w", err)
	}
	summary.Pods = len(pods.Items)

	var findings []domain.Finding
	deployments, err := s.client.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, summary, fmt.Errorf("list deployments: %w", err)
	}
	for _, d := range deployments.Items {
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		if desired > d.Status.AvailableReplicas {
			findings = append(findings, workloadFinding(clusterID, d.Namespace, "Deployment", d.Name, "reliability", "high", "Deployment has unavailable replicas", fmt.Sprintf("Deployment has %d available replicas out of %d desired.", d.Status.AvailableReplicas, desired), "Inspect rollout with kubectl rollout status deployment/"+d.Name+" -n "+d.Namespace))
		}
	}
	statefulSets, err := s.client.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, summary, fmt.Errorf("list statefulsets: %w", err)
	}
	for _, st := range statefulSets.Items {
		desired := int32(1)
		if st.Spec.Replicas != nil {
			desired = *st.Spec.Replicas
		}
		if desired > st.Status.ReadyReplicas {
			findings = append(findings, workloadFinding(clusterID, st.Namespace, "StatefulSet", st.Name, "reliability", "high", "StatefulSet has unavailable replicas", fmt.Sprintf("StatefulSet has %d ready replicas out of %d desired.", st.Status.ReadyReplicas, desired), "Inspect StatefulSet pods and events in namespace "+st.Namespace+"."))
		}
	}
	for _, pod := range pods.Items {
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if pod.Status.Phase == corev1.PodPending {
			findings = append(findings, finding(clusterID, pod, "reliability", "high", "Pod is pending", "The Pod has not been scheduled or started.", "Inspect scheduling events with kubectl describe pod "+pod.Name+" -n "+pod.Namespace))
		}
		ready := isPodReady(pod)
		if !ready {
			summary.UnhealthyPods++
			findings = append(findings, finding(clusterID, pod, "reliability", "high",
				"Pod is not ready", "The Pod is not reporting Ready. Check events, container status and application health endpoints.",
				"Inspect: kubectl describe pod "+pod.Name+" -n "+pod.Namespace))
		}
		restarts := int32(0)
		for _, status := range pod.Status.ContainerStatuses {
			restarts += status.RestartCount
		}
		if restarts >= 3 {
			summary.RestartingPods++
			findings = append(findings, finding(clusterID, pod, "reliability", "medium",
				"Container restart count is elevated", fmt.Sprintf("Containers in this Pod have restarted %d times.", restarts),
				"Inspect previous logs with kubectl logs "+pod.Name+" -n "+pod.Namespace+" --previous"))
		}
		for _, status := range pod.Status.ContainerStatuses {
			if status.State.Waiting == nil {
				continue
			}
			switch status.State.Waiting.Reason {
			case "CrashLoopBackOff":
				findings = append(findings, containerFinding(clusterID, pod, status.Name, "reliability", "high", "Container is in CrashLoopBackOff", "Container repeatedly exits and Kubernetes is backing off restart attempts.", "Inspect current and previous logs, then check application startup configuration."))
			case "ImagePullBackOff", "ErrImagePull":
				findings = append(findings, containerFinding(clusterID, pod, status.Name, "reliability", "high", "Container image cannot be pulled", "Kubernetes cannot retrieve the configured container image: "+status.State.Waiting.Reason+".", "Verify the image name, tag, registry availability and imagePullSecrets."))
			}
		}
		for _, c := range pod.Spec.Containers {
			if c.SecurityContext != nil && c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
				findings = append(findings, containerFinding(clusterID, pod, c.Name, "security", "high", "Privilege escalation allowed", "Container explicitly allows privilege escalation.", "Set allowPrivilegeEscalation: false unless required."))
			}
			if c.Resources.Requests.Cpu().IsZero() || c.Resources.Requests.Memory().IsZero() {
				findings = append(findings, containerFinding(clusterID, pod, c.Name, "capacity", "medium", "Resource requests missing", "Container does not specify both CPU and memory requests.", "Set appropriate requests after measuring workload usage."))
			}
			if c.Resources.Limits.Cpu().IsZero() || c.Resources.Limits.Memory().IsZero() {
				findings = append(findings, containerFinding(clusterID, pod, c.Name, "capacity", "low", "Resource limits missing", "Container does not specify both CPU and memory limits.", "Set CPU and memory limits appropriate to the workload and cluster policy."))
			}

			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				findings = append(findings, containerFinding(clusterID, pod, c.Name, "security", "critical",
					"Privileged container detected", "A privileged container has broad access to the host kernel.",
					"Remove privileged: true unless a documented, reviewed exception is required."))
			}
			if c.SecurityContext == nil || c.SecurityContext.RunAsNonRoot == nil || !*c.SecurityContext.RunAsNonRoot {
				findings = append(findings, containerFinding(clusterID, pod, c.Name, "security", "medium",
					"Container may run as root", "The container does not explicitly require a non-root user.",
					"Set securityContext.runAsNonRoot: true and configure a non-root image user."))
			}
		}
	}
	return findings, summary, nil
}

func isPodReady(p corev1.Pod) bool {
	if p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func finding(clusterID string, pod corev1.Pod, category, severity, title, description, remediation string) domain.Finding {
	raw := clusterID + "|" + pod.Namespace + "|" + pod.Name + "|" + category + "|" + title
	sum := sha256.Sum256([]byte(raw))
	return domain.Finding{
		ClusterID: clusterID, Namespace: pod.Namespace, Resource: "Pod", ResourceName: pod.Name,
		Category: category, Severity: severity, Title: title, Description: description,
		Remediation: remediation, Fingerprint: hex.EncodeToString(sum[:]), DetectedAt: time.Now().UTC(), Status: "open",
	}
}

func workloadFinding(clusterID, namespace, resource, name, category, severity, title, description, remediation string) domain.Finding {
	raw := strings.Join([]string{clusterID, namespace, resource, name, category, title}, "|")
	sum := sha256.Sum256([]byte(raw))
	return domain.Finding{ClusterID: clusterID, Namespace: namespace, Resource: resource, ResourceName: name, Category: category, Severity: severity, Title: title, Description: description, Remediation: remediation, Fingerprint: hex.EncodeToString(sum[:]), DetectedAt: time.Now().UTC(), Status: "open"}
}

type unavailableScanner struct{ err error }

func NewUnavailableScanner(err error) Scanner { return unavailableScanner{err: err} }
func (u unavailableScanner) Scan(context.Context, string) ([]domain.Finding, domain.ScanSummary, error) {
	return nil, domain.ScanSummary{}, fmt.Errorf("Kubernetes scanner unavailable: %w", u.err)
}

func containerFinding(clusterID string, pod corev1.Pod, container, category, severity, title, description, remediation string) domain.Finding {
	f := finding(clusterID, pod, category, severity, title, description+" Container: "+container+".", remediation)
	raw := strings.Join([]string{clusterID, pod.Namespace, pod.Name, container, category, title}, "|")
	sum := sha256.Sum256([]byte(raw))
	f.Fingerprint = hex.EncodeToString(sum[:])
	return f
}
