package util

import (
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/kubernetes/pkg/apis/rbac"
)

func GetAllowedSubjects(namespace string, subjects []rbac.Subject) (sets.String, sets.String) {
	users := sets.String{}
	groups := sets.String{}
	for _, subject := range subjects {
		switch subject.Kind {
		case rbac.UserKind:
			users.Insert(subject.Name)
		case rbac.GroupKind:
			groups.Insert(subject.Name)
		case rbac.ServiceAccountKind:
			// default the namespace to namespace we're working in if
			// it's available. This allows rolebindings that reference
			// SAs in the local namespace to avoid having to qualify
			// them.
			ns := namespace
			if len(subject.Namespace) > 0 {
				ns = subject.Namespace
			}
			if len(ns) >= 0 {
				name := serviceaccount.MakeUsername(ns, subject.Name)
				users.Insert(name)
			}
		default:
			continue // TODO, should this add errs?
		}

	}
	return users, groups
}
