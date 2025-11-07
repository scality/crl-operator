package utils

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Update labels on an Object
func UpdateLabels(object metav1.Object, labels map[string]string) {
	current := object.GetLabels()
	if current == nil {
		current = make(map[string]string)
	}

	for k, v := range labels {
		current[k] = v
	}

	object.SetLabels(current)
}
