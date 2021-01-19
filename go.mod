module github.com/rancher/fleet

go 1.14

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v14.0.0+incompatible
	github.com/rancher/fleet/pkg/apis => ./pkg/apis
	helm.sh/helm/v3 => github.com/ibuildthecloud/helm/v3 v3.1.0-rc.1.0.20200829031744-19e92760f498
	k8s.io/client-go => github.com/rancher/client-go v0.18.8-fleet1
)

require (
	github.com/Masterminds/semver/v3 v3.1.0
	github.com/cheggaaa/pb v1.0.27
	github.com/evanphx/json-patch v4.9.0+incompatible // indirect
	github.com/go-git/go-git/v5 v5.2.0
	github.com/go-openapi/spec v0.19.5
	github.com/google/go-cmp v0.5.2 // indirect
	github.com/google/go-containerregistry v0.1.1
	github.com/gregjones/httpcache v0.0.0-20190212212710-3befbb6ad0cc // indirect
	github.com/hashicorp/go-getter v1.4.1
	github.com/json-iterator/go v1.1.10 // indirect
	github.com/pkg/errors v0.9.1
	github.com/rancher/fleet/pkg/apis v0.0.0
	github.com/rancher/gitjob v0.1.5
	github.com/rancher/lasso v0.0.0-20200905045615-7fcb07d6a20b
	github.com/rancher/wrangler v0.7.3-0.20201002224307-4303c423125a
	github.com/rancher/wrangler-cli v0.0.0-20200815040857-81c48cf8ab43
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	go.mozilla.org/sops/v3 v3.6.1
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b // indirect
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a
	golang.org/x/text v0.3.4 // indirect
	golang.org/x/tools v0.0.0-20200916195026-c9a70fc28ce3 // indirect
	helm.sh/helm/v3 v3.0.0
	k8s.io/api v0.18.8
	k8s.io/apimachinery v0.18.8
	k8s.io/cli-runtime v0.18.4
	k8s.io/client-go v0.18.8
	k8s.io/gengo v0.0.0-20201113003025-83324d819ded // indirect
	k8s.io/klog/v2 v2.4.0 // indirect
	rsc.io/letsencrypt v0.0.3 // indirect
	sigs.k8s.io/cli-utils v0.16.0
	sigs.k8s.io/kustomize/api v0.6.0
	sigs.k8s.io/kustomize/kyaml v0.7.1
	sigs.k8s.io/yaml v1.2.0
)
