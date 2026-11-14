package kube

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPodReady(t *testing.T) {
	for _, tc := range []struct {
		name string
		pod  corev1.Pod
		want bool
	}{
		{"pending", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending}}, false},
		{"running ready", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}, true},
		{"running unready", corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPodReady(tc.pod); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
func TestContainerFingerprintsUnique(t *testing.T) {
	pod := corev1.Pod{}
	pod.Namespace = "default"
	pod.Name = "app"
	a := containerFinding("cluster", pod, "a", "security", "high", "issue", "desc", "fix")
	b := containerFinding("cluster", pod, "b", "security", "high", "issue", "desc", "fix")
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("container findings must have different fingerprints")
	}
}

func TestScannerDetectsPendingImagePullAndUnavailableDeployment(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "missing:latest"}}}, Status: corev1.PodStatus{Phase: corev1.PodPending, ContainerStatuses: []corev1.ContainerStatus{{Name: "web", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}}}}}
	deployment := appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web"}, Spec: appsv1.DeploymentSpec{Replicas: int32ptr(2)}, Status: appsv1.DeploymentStatus{AvailableReplicas: 1}}
	client := fake.NewSimpleClientset(&pod, &deployment)
	scanner := &KubernetesScanner{client: client}
	findings, summary, err := scanner.Scan(context.Background(), "test-cluster")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Pods != 1 {
		t.Fatalf("pods = %d, want 1", summary.Pods)
	}
	wanted := map[string]bool{"Pod is pending": false, "Container image cannot be pulled": false, "Deployment has unavailable replicas": false}
	for _, f := range findings {
		if _, ok := wanted[f.Title]; ok {
			wanted[f.Title] = true
		}
	}
	for title, found := range wanted {
		if !found {
			t.Errorf("expected finding %q", title)
		}
	}
}

func int32ptr(v int32) *int32 { return &v }
