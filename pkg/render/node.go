package render

import (
	operatorv1alpha1 "github.com/projectcalico/operator/pkg/apis/operator/v1alpha1"

	apps "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func Node(cr *operatorv1alpha1.Core) []runtime.Object {
	return []runtime.Object{
		nodeServiceAccount(cr),
		nodeRole(cr),
		nodeRoleBinding(cr),
		nodeDaemonset(cr),
	}
}

func nodeServiceAccount(cr *operatorv1alpha1.Core) *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: "kube-system",
			Labels:    map[string]string{},
		},
	}
}

func nodeRoleBinding(cr *operatorv1alpha1.Core) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: "kube-system",
			Labels:    map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "calico-node",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "calico-node",
				Namespace: "kube-system",
			},
		},
	}
}

func nodeRole(cr *operatorv1alpha1.Core) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: "kube-system",
			Labels:    map[string]string{},
		},
		// TODO: Comments explaining why each permission is needed.
		Rules: []rbacv1.PolicyRule{
			{
				// The CNI plugin needs to get pods, nodes, namespaces.
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get"},
			},
			{
				// Used to discover Typha endpoints and service IPs for advertisement.
				APIGroups: []string{""},
				Resources: []string{"endpoints", "services"},
				Verbs:     []string{"watch", "list", "get"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"nodes/status"},
				Verbs:     []string{"patch", "update"},
			},
			{
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"watch", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "namespaces", "serviceaccounts"},
				Verbs:     []string{"watch", "list"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/status"},
				Verbs:     []string{"patch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"bgpconfigurations",
					"bgppeers",
					"clusterinformations",
					"felixconfigurations",
					"globalnetworkpolicies",
					"globalnetworksets",
					"hostendpoints",
					"ipamblocks",
					"ippools",
					"networkpolicies",
					"networksets",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				// For migration code only. Remove when no longer needed.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"globalbgpconfigs",
					"globalfelixconfigs",
				},
				Verbs: []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"clusterinformations",
					"felixconfigurations",
					"ippools",
				},
				Verbs: []string{"create", "update"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{
					"blockaffinities",
					"ipamblocks",
					"ipamhandles",
				},
				Verbs: []string{"get", "list", "create", "update", "delete"},
			},
			{
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"ipamconfigs"},
				Verbs:     []string{"get"},
			},
			{
				// confd watches block affinities for route aggregation.
				APIGroups: []string{"crd.projectcalico.org"},
				Resources: []string{"blockaffinities"},
				Verbs:     []string{"watch"},
			},
		},
	}
}

func nodeDaemonset(cr *operatorv1alpha1.Core) *apps.DaemonSet {
	var terminationGracePeriod int64 = 0
	var trueBool bool = true
	var fileOrCreate v1.HostPathType = v1.HostPathFileOrCreate
	return &apps.DaemonSet{
		TypeMeta: metav1.TypeMeta{Kind: "DaemonSet", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-node",
			Namespace: "kube-system",
			Labels:    map[string]string{},
		},
		Spec: apps.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "calico-node"}},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app": "calico-node",
					},
				},
				Spec: v1.PodSpec{
					NodeSelector: map[string]string{},
					Tolerations: []v1.Toleration{
						{Operator: "Exists", Effect: "NoSchedule"},
						{Operator: "Exists", Effect: "NoExecute"},
						// TODO: Not valid?? {Operator: "Exists", Effect: "CriticalAddonsOnly"},
					},
					ServiceAccountName:            "calico-node",
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					HostNetwork:                   true,
					InitContainers: []v1.Container{
						{
							Name:    "install-cni",
							Image:   "calico/cni:v3.7.2",
							Command: []string{"/install-cni.sh"},
							Env: []v1.EnvVar{
								{Name: "CNI_CONF_NAME", Value: "10-calico.conflist"},
								{Name: "CNI_MTU", Value: "1440"},
								{Name: "SLEEP", Value: "false"},
								{Name: "CNI_NETWORK_CONFIG", Value: "TODO"},
								{
									Name: "KUBERNETES_NODE_NAME",
									ValueFrom: &v1.EnvVarSource{
										FieldRef: &v1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
									},
								},
								// TODO: Change this for Openshift.
								{Name: "CNI_NET_DIR", Value: "/etc/cni/net.d"},
							},
							VolumeMounts: []v1.VolumeMount{
								{MountPath: "/host/opt/cni/bin", Name: "cni-bin-dir"},
								{MountPath: "/host/etc/cni/net.d", Name: "cni-net-dir"},
							},
						},
					},
					Containers: []v1.Container{
						{
							Name:            "calico-node",
							Image:           "calico/node:v3.7.2",
							SecurityContext: &v1.SecurityContext{Privileged: &trueBool},
							Env: []v1.EnvVar{
								{Name: "DATASTORE_TYPE", Value: "kubernetes"},
								{Name: "WAIT_FOR_DATASTORE", Value: "true"},
								{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
								{Name: "CLUSTER_TYPE", Value: "k8s,bgp,operator"},
								{Name: "IP", Value: "autodetect"},
								{Name: "CALICO_IPV4POOL_CIDR", Value: "192.168.0.0/16"},
								{Name: "CALICO_IPV4POOL_IPIP", Value: "Always"},
								{Name: "CALICO_DISABLE_FILE_LOGGING", Value: "true"},
								{Name: "FELIX_IPINIPMTU", Value: "1440"},
								{Name: "FELIX_DEFAULTENDPOINTTOHOSTACTION", Value: "ACCEPT"},
								{Name: "FELIX_IPV6SUPPORT", Value: "false"},
								{Name: "FELIX_HEALTHENABLED", Value: "true"},
								{
									Name: "NODOENAME",
									ValueFrom: &v1.EnvVarSource{
										FieldRef: &v1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
									},
								},
							},
							VolumeMounts: []v1.VolumeMount{
								{MountPath: "/lib/modules", Name: "lib-modules", ReadOnly: true},
								{MountPath: "/run/xtables.lock", Name: "xtables-lock"},
								{MountPath: "/var/run/calico", Name: "var-run-calico"},
								{MountPath: "/var/lib/calico", Name: "var-lib-calico"},
							},
						},
					},
					Volumes: []v1.Volume{
						{Name: "lib-modules", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/lib/modules"}}},
						{Name: "var-run-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/run/calico"}}},
						{Name: "var-lib-calico", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/var/lib/calico"}}},
						{Name: "xtables-lock", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/run/xtables.lock", Type: &fileOrCreate}}},
						// TODO: Change these for OpenShift.
						{Name: "cni-bin-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/etc/kubernetes/cni/bin"}}},
						{Name: "cni-net-dir", VolumeSource: v1.VolumeSource{HostPath: &v1.HostPathVolumeSource{Path: "/etc/kubernetes/cni/net.d"}}},
					},
				},
			},
		},
	}
}