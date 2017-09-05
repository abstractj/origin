package localresourceaccessreview

import (
	"errors"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	kauthorizer "k8s.io/apiserver/pkg/authorization/authorizer"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	"github.com/openshift/origin/pkg/authorization/registry/resourceaccessreview"
	"github.com/openshift/origin/pkg/authorization/registry/util"
	"github.com/openshift/origin/pkg/quota/controller/clusterquotamapping"
	"github.com/openshift/origin/pkg/util/restoptions"
	"github.com/openshift/origin/pkg/cmd/server/origin"
	"time"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	fakeinternal "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
	kinternalinformers "k8s.io/kubernetes/pkg/client/informers/informers_generated/internalversion"
	authorizationinformer "github.com/openshift/origin/pkg/authorization/generated/informers/internalversion"
	authorizationclientfake "github.com/openshift/origin/pkg/authorization/generated/internalclientset/fake"
	quotainformer "github.com/openshift/origin/pkg/quota/generated/informers/internalversion"
	quotaclientfake "github.com/openshift/origin/pkg/quota/generated/internalclientset/fake"
	securityinformer "github.com/openshift/origin/pkg/security/generated/informers/internalversion"
	securityclientfake "github.com/openshift/origin/pkg/security/generated/internalclientset/fake"
	sccstorage "github.com/openshift/origin/pkg/security/registry/securitycontextconstraints/etcd"
	apiserver "k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"
	kclientsetexternal "k8s.io/kubernetes/pkg/client/clientset_generated/clientset"
	kclientsetinternal "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	kubeletclient "k8s.io/kubernetes/pkg/kubelet/client"
)

type resourceAccessTest struct {
	authorizer    *testAuthorizer
	reviewRequest *authorizationapi.LocalResourceAccessReview
}

type testAuthorizer struct {
	users  sets.String
	groups sets.String
	err    string

	actualAttributes kauthorizer.Attributes
}

func (a *testAuthorizer) Authorize(attributes kauthorizer.Attributes) (allowed bool, reason string, err error) {
	// allow the initial check for "can I run this RAR at all"
	if attributes.GetResource() == "localresourceaccessreviews" {
		return true, "", nil
	}

	return false, "", errors.New("Unsupported")
}
func (a *testAuthorizer) GetAllowedSubjects(passedAttributes kauthorizer.Attributes) (sets.String, sets.String, error) {
	a.actualAttributes = passedAttributes
	if len(a.err) == 0 {
		return a.users, a.groups, nil
	}
	return a.users, a.groups, errors.New(a.err)
}

func TestNoNamespace(t *testing.T) {
	test := &resourceAccessTest{
		authorizer: &testAuthorizer{
			err: "namespace is required on this type: ",
		},
		reviewRequest: &authorizationapi.LocalResourceAccessReview{
			Action: authorizationapi.Action{
				Namespace: "",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}

	test.runTest(t)
}

func TestConflictingNamespace(t *testing.T) {
	authorizer := &testAuthorizer{}
	config := fakeOpenshiftAPIServerConfig()
	reviewRequest := &authorizationapi.LocalResourceAccessReview{
		Action: authorizationapi.Action{
			Namespace: "foo",
			Verb:      "get",
			Resource:  "pods",
		},
	}

	storage := NewREST(resourceaccessreview.NewRegistry(resourceaccessreview.NewREST(authorizer, config.SubjectLocator)))
	ctx := apirequest.WithNamespace(apirequest.NewContext(), "bar")
	_, err := storage.Create(ctx, reviewRequest, false)
	if err == nil {
		t.Fatalf("unexpected non-error: %v", err)
	}
	if e, a := `namespace: Invalid value: "foo": namespace must be: bar`, err.Error(); e != a {
		t.Fatalf("expected %v, got %v", e, a)
	}
}

func TestEmptyReturn(t *testing.T) {
	test := &resourceAccessTest{
		authorizer: &testAuthorizer{
			users:  sets.String{},
			groups: sets.String{},
		},
		reviewRequest: &authorizationapi.LocalResourceAccessReview{
			Action: authorizationapi.Action{
				Namespace: "unittest",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}

	test.runTest(t)
}

func TestNoErrors(t *testing.T) {
	test := &resourceAccessTest{
		authorizer: &testAuthorizer{
			users:  sets.NewString("one", "two"),
			groups: sets.NewString("three", "four"),
		},
		reviewRequest: &authorizationapi.LocalResourceAccessReview{
			Action: authorizationapi.Action{
				Namespace: "unittest",
				Verb:      "delete",
				Resource:  "deploymentConfig",
			},
		},
	}

	test.runTest(t)
}

func (r *resourceAccessTest) runTest(t *testing.T) {
	config := fakeOpenshiftAPIServerConfig()
	storage := NewREST(resourceaccessreview.NewRegistry(resourceaccessreview.NewREST(r.authorizer, config.SubjectLocator)))

	expectedResponse := &authorizationapi.ResourceAccessReviewResponse{
		Namespace: r.reviewRequest.Action.Namespace,
		Users:     r.authorizer.users,
		Groups:    r.authorizer.groups,
	}

	expectedAttributes := util.ToDefaultAuthorizationAttributes(nil, r.reviewRequest.Action.Namespace, r.reviewRequest.Action)

	ctx := apirequest.WithNamespace(apirequest.WithUser(apirequest.NewContext(), &user.DefaultInfo{}), r.reviewRequest.Action.Namespace)
	obj, err := storage.Create(ctx, r.reviewRequest, false)
	if err != nil && len(r.authorizer.err) == 0 {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.authorizer.err) != 0 {
		if err == nil {
			t.Fatalf("unexpected non-error: %v", err)
		}
		if e, a := r.authorizer.err, err.Error(); e != a {
			t.Fatalf("expected %v, got %v", e, a)
		}

		return
	}

	switch obj.(type) {
	case *authorizationapi.ResourceAccessReviewResponse:
		if !reflect.DeepEqual(expectedResponse, obj) {
			t.Errorf("diff %v", diff.ObjectGoPrintDiff(expectedResponse, obj))
		}
	case nil:
		if len(r.authorizer.err) == 0 {
			t.Fatal("unexpected nil object")
		}
	default:
		t.Errorf("Unexpected obj type: %v", obj)
	}

	if !reflect.DeepEqual(expectedAttributes, r.authorizer.actualAttributes) {
		t.Errorf("diff %v", diff.ObjectGoPrintDiff(expectedAttributes, r.authorizer.actualAttributes))
	}
}


func fakeOpenshiftAPIServerConfig() *origin.OpenshiftAPIConfig {
	internalkubeInformerFactory := kinternalinformers.NewSharedInformerFactory(fakeinternal.NewSimpleClientset(), 1*time.Second)
	authorizationInformerFactory := authorizationinformer.NewSharedInformerFactory(authorizationclientfake.NewSimpleClientset(), 0)
	quotaInformerFactory := quotainformer.NewSharedInformerFactory(quotaclientfake.NewSimpleClientset(), 0)
	securityInformerFactory := securityinformer.NewSharedInformerFactory(securityclientfake.NewSimpleClientset(), 0)
	restOptionsGetter := restoptions.NewSimpleGetter(&storagebackend.Config{ServerList: []string{"localhost"}})
	sccStorage := sccstorage.NewREST(restOptionsGetter)

	ret := &origin.OpenshiftAPIConfig{
		GenericConfig: &apiserver.Config{
			LoopbackClientConfig: &restclient.Config{},
			RESTOptionsGetter:    restOptionsGetter,
		},

		KubeClientExternal:            &kclientsetexternal.Clientset{},
		KubeClientInternal:            &kclientsetinternal.Clientset{},
		KubeletClientConfig:           &kubeletclient.KubeletClientConfig{},
		KubeInternalInformers:         internalkubeInformerFactory,
		AuthorizationInformers:        authorizationInformerFactory,
		QuotaInformers:                quotaInformerFactory,
		SecurityInformers:             securityInformerFactory,
		SCCStorage:                    sccStorage,
		EnableBuilds:                  true,
		ClusterQuotaMappingController: clusterquotamapping.NewClusterQuotaMappingControllerInternal(internalkubeInformerFactory.Core().InternalVersion().Namespaces(), quotaInformerFactory.Quota().InternalVersion().ClusterResourceQuotas()),
	}
	return ret
}