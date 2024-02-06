// Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ApplicationLayerSpec defines the desired state of ApplicationLayer
type ApplicationLayerSpec struct {
	// WebApplicationFirewall controls whether or not ModSecurity enforcement is enabled for the cluster.
	// When enabled, Services may opt-in to having ingress traffic examed by ModSecurity.
	WebApplicationFirewall *WAFStatusType `json:"webApplicationFirewall,omitempty"`
	// Specification for application layer (L7) log collection.
	LogCollection *LogCollectionSpec `json:"logCollection,omitempty"`
	// Application Layer Policy controls whether or not ALP enforcement is enabled for the cluster.
	// When enabled, NetworkPolicies with HTTP Match rules may be defined to opt-in workloads for traffic enforcement on the application layer.
	ApplicationLayerPolicy *ApplicationLayerPolicyStatusType `json:"applicationLayerPolicy,omitempty"`
	// User-configurable settings for the Envoy proxy.
	EnvoySettings *EnvoySettings `json:"envoy,omitempty"`
	// Istio struct defines the configuration for the Istio service mesh control plane.
	// It controls the installation of Istio using the IstioOperator Custom Resource (CR).
	// This struct specifies the configuration for the IstioOperator CR, which details
	// the settings and options for the Istio installation. Additionally, it includes
	// a Web Application Firewall (WAF) configuration
	// +optional
	Istio IstioConfig `json:"istio,omitempty"`
}

type LogCollectionStatusType string
type WAFStatusType string
type ApplicationLayerPolicyStatusType string

const (
	WAFDisabled                    WAFStatusType                    = "Disabled"
	WAFEnabled                     WAFStatusType                    = "Enabled"
	L7LogCollectionDisabled        LogCollectionStatusType          = "Disabled"
	L7LogCollectionEnabled         LogCollectionStatusType          = "Enabled"
	ApplicationLayerPolicyEnabled  ApplicationLayerPolicyStatusType = "Enabled"
	ApplicationLayerPolicyDisabled ApplicationLayerPolicyStatusType = "Disabled"
)

type EnvoySettings struct {
	// The number of additional ingress proxy hops from the right side of the
	// x-forwarded-for HTTP header to trust when determining the origin client’s
	// IP address. 0 is permitted, but >=1 is the typical setting.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=2147483647
	// +kubebuilder:default:=0
	// +optional
	XFFNumTrustedHops int32 `json:"xffNumTrustedHops,omitempty"`
	// If set to true, the Envoy connection manager will use the real remote address
	// of the client connection when determining internal versus external origin and
	// manipulating various headers.
	// +kubebuilder:default:=false
	// +optional
	UseRemoteAddress bool `json:"useRemoteAddress,omitempty"`
}

type LogCollectionSpec struct {
	// This setting enables or disable log collection.
	// Allowed values are Enabled or Disabled.
	// +optional
	CollectLogs *LogCollectionStatusType `json:"collectLogs,omitempty"`

	// Interval in seconds for sending L7 log information for processing.
	// +optional
	// Default: 5 sec
	LogIntervalSeconds *int64 `json:"logIntervalSeconds,omitempty"`

	// Maximum number of unique L7 logs that are sent LogIntervalSeconds.
	// Adjust this to limit the number of L7 logs sent per LogIntervalSeconds
	// to felix for further processing, use negative number to ignore limits.
	// +optional
	// Default: -1
	LogRequestsPerInterval *int64 `json:"logRequestsPerInterval,omitempty"`
}

type IstioConfig struct {
	// sidecarInjectorWebhookOverride allow users to override the sidecar injector webhook configurations, enabling
	// the injection of custom sidecar templates alongside the Tigera owned dikastes template for WAF functionality.
	// sidecarInjectorWebhookOverride is an optional field that enables the customization of the sidecar injector
	// webhook configuration. Users can utilize this field to inject custom sidecar templates in addition to the
	// Tigera-provided dikastes sidecar template for WAF functionality. This customization is crucial when deploying
	// custom sidecar injector templates due to the IstioOperator CR's limitation, which supports only a single instance
	// per cluster. Specifying custom templates here ensures that previous custom sidecar injection configurations are
	// not overwritten. Although this field is essential for deploying custom templates, it remains optional for other use cases.
	// Configuration through this field allows the tigera-operator to consolidate all custom sidecar injection templates
	// into a single IstioOperator CR, promoting configuration unity and preventing conflicts.
	// +optional
	SidecarInjectorWebhook SidecarInjectorWebhookOverride `json:"sidecarInjectorWebhookOverride,omitempty"`
	// Waf defines the configurations for the Web Application Firewall (WAF) functionality.
	// This includes settings that allow the enablement of WAF functionality for the Istio
	// Ingress Gateway.
	// +optional
	Waf *WafConfig `json:"waf,omitempty"`
}

// SidecarInjectorWebhookOverride contains optional overrides for the sidecar injector webhook.
type SidecarInjectorWebhookOverride struct {
	// Templates allow users to specify custom templates for sidecar injection. The field expects a map where the key
	// is the template name, and the value is a Kubernetes container specification object.
	// More Info: https://istio.io/latest/docs/setup/additional-setup/sidecar-injection/#custom-templates-experimental
	Templates map[string]corev1.PodSpec `json:"templates,omitempty"`
}

type WafConfig struct {
	// ListenPort specifies the port on which the Web Application Firewall (WAF) listens.
	// This is an optional field. By default, WAF listens on port 5051. If there is a need
	// to run the WAF service on a different port, this field can be configured accordingly.
	// It is important to ensure that no two services are running on the same port to avoid
	// port conflicts.
	// +optional
	ListenPort int `json:"listenPort,omitempty"`
	// Workloads is a mandatory field that specifies the list of workloads for which the Web Application
	// Firewall (WAF) needs to be enabled. Each workload is defined by the Workload struct, which includes
	// details such as the name, namespace, context and specific labels for identifying the workload. The WAF
	// functionality will be applied to these specified workloads to enhance their ingress traffic security.
	Workloads []Workload `json:"workloads"`
}

type Workload struct {
	// Name specifies the name of the EnvoyFilter which will direct the traffic to Dikastes for consulting the Web
	// Application Firewall (WAF) functionality. The tigera-operator will automatically prefix this name with "tigera."
	// and suffix it with ".waf-ext-authz" to signify that it is controlled by Tigera and used for external authorization
	// for WAF. This name should be unique, and an ideal way to construct a name that ensures uniqueness is to follow the
	// pattern "<namespace>.<context>.<application-name>". This naming convention helps in effectively identifying
	// and managing the EnvoyFilters in the context of WAF.
	Name string `json:"name"`
	// Namespace specifies the Kubernetes namespace for which the EnvoyFilter will be applicable. This determines the
	// scope of the EnvoyFilter's effect within the Kubernetes cluster. If the specified namespace is the Istio
	// rootNamespace (i.e., the namespace in which Istio is installed), then the EnvoyFilter becomes a global filter,
	// applying to workloads across all namespaces, provided their labels match the specified criteria.
	Namespace string `json:"namespace"`
	// Context specifies the context of the EnvoyFilter within the Istio service mesh. The value of this field will
	// always be "gateway" for the Istio Gateway (either ingress or egress) and "sidecar" for Istio workloads. This
	// field is crucial in determining the operational context of the EnvoyFilter, whether it is meant to be applied
	// to traffic flowing through the Istio Gateway or to traffic within the individual Istio workloads (sidecars).
	// +kubebuilder:validation:Enum=gateway;sidecar
	Context string `json:"context"`
	// Labels specify the workload labels for which the EnvoyFilter is applicable. This field is mandatory; otherwise,
	// the EnvoyFilter will be applied to all workloads within the specified Kubernetes namespace, potentially disrupting
	// the normal functionality of services where the EnvoyFilter's context matches. The ideal way to set this value is by
	// copying the label values from Kubernetes deployment units (such as pods, deployments, daemonsets, or any other
	// Kubernetes building blocks that deploy pods). These labels ensure that the EnvoyFilter is targeted precisely to the
	// intended workloads, based on their label selectors.
	Labels map[string]string `json:"labels"`
}

// ApplicationLayerStatus defines the observed state of ApplicationLayer
type ApplicationLayerStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ApplicationLayer is the Schema for the applicationlayers API
type ApplicationLayer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApplicationLayerSpec   `json:"spec,omitempty"`
	Status ApplicationLayerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ApplicationLayerList contains a list of ApplicationLayer
type ApplicationLayerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApplicationLayer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ApplicationLayer{}, &ApplicationLayerList{})
}
