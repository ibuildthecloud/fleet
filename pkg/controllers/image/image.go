package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/rancher/fleet/pkg/update"
	"github.com/sirupsen/logrus"

	"github.com/Masterminds/semver/v3"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/rancher/fleet/pkg/apis/fleet.cattle.io/v1alpha1"
	fleetcontrollers "github.com/rancher/fleet/pkg/generated/controllers/fleet.cattle.io/v1alpha1"
	corev1controler "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/pkg/kstatus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var (
	lock sync.Mutex
)

const (
	// AlphabeticalOrderAsc ascending order
	AlphabeticalOrderAsc = "ASC"
	// AlphabeticalOrderDesc descending order
	AlphabeticalOrderDesc = "DESC"

	defaultMessageTemplate = `Update from image update automation`
)

func Register(ctx context.Context, core corev1controler.Interface, gitRepos fleetcontrollers.GitRepoController, images fleetcontrollers.ImageScanController) error {
	h := handler{
		secretCache:  core.Secret().Cache(),
		gitrepoCache: gitRepos.Cache(),
	}

	fleetcontrollers.RegisterImageScanStatusHandler(ctx, images, "ImageScanned", "image-scan", h.onChange)
	return nil
}

type handler struct {
	secretCache  corev1controler.SecretCache
	gitrepoCache fleetcontrollers.GitRepoCache
}

func (h handler) onChange(image *v1alpha1.ImageScan, status v1alpha1.ImageScanStatus) (v1alpha1.ImageScanStatus, error) {
	if image == nil || image.DeletionTimestamp != nil {
		return status, nil
	}

	if image.Spec.Suspend {
		return status, nil
	}

	ref, err := name.ParseReference(image.Spec.Image)
	if err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}

	canonical := ref.Context().String()
	if canonical != status.CanonicalImageName {
		status.CanonicalImageName = canonical
	}

	if !shouldScan(image) {
		return status, nil
	}

	var options []remote.Option
	if image.Spec.SecretRef != nil {
		secret, err := h.secretCache.Get(image.Namespace, image.Spec.SecretRef.Name)
		if err != nil {
			kstatus.SetError(image, err.Error())
			return status, err
		}
		auth, err := authFromSecret(secret, ref.Context().RegistryStr())
		if err != nil {
			kstatus.SetError(image, err.Error())
			return status, err
		}
		options = append(options, remote.WithAuth(auth))
	}

	tags, err := remote.ListWithContext(context.Background(), ref.Context(), options...)
	if err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}

	status.LastScanTags = tags
	status.LastScanTime = metav1.NewTime(time.Now())

	latestTag, err := latestTag(image.Spec.Policy, tags)
	if err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}

	status.LatestTag = latestTag
	status.LatestImage = status.CanonicalImageName + ":" + latestTag

	if image.Spec.GitRepoName == "" {
		return status, nil
	}

	gitrepo, err := h.gitrepoCache.Get(image.Namespace, image.Spec.GitRepoName)
	if err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}

	lock.Lock()
	defer lock.Unlock()
	// todo: maybe we should preserve the dir
	tmp, err := ioutil.TempDir("", fmt.Sprintf("%s-%s", image.Namespace, image.Spec.GitRepoName))
	if err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}
	defer os.RemoveAll(tmp)

	auth, err := h.auth(gitrepo)
	if err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}

	repo, err := gogit.PlainClone(tmp, false, &gogit.CloneOptions{
		URL:           gitrepo.Spec.Repo,
		Auth:          auth,
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(gitrepo.Spec.Branch),
		SingleBranch:  true,
		Depth:         1,
		Progress:      nil,
		Tags:          gogit.NoTags,
	})
	if err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}

	if err := update.UpdateWithSetters(tmp, tmp, []v1alpha1.ImageScan{*image}); err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}

	commit, err := commitAllAndPush(context.Background(), repo, auth, image.Spec.Commit)
	if err != nil {
		kstatus.SetError(image, err.Error())
		return status, err
	}
	logrus.Infof("Repo %s, commit %s pushed", gitrepo.Spec.Repo, commit)
	return status, nil
}

func commitAllAndPush(ctx context.Context, repo *gogit.Repository, auth transport.AuthMethod, commit v1alpha1.CommitSpec) (string, error) {
	working, err := repo.Worktree()
	if err != nil {
		return "", err
	}

	status, err := working.Status()
	if err != nil {
		return "", err
	} else if status.IsClean() {
		return "", nil
	}

	msgTmpl := commit.MessageTemplate
	if msgTmpl == "" {
		msgTmpl = defaultMessageTemplate
	}
	tmpl, err := template.New("commit message").Parse(msgTmpl)
	if err != nil {
		return "", err
	}
	buf := &strings.Builder{}
	if err := tmpl.Execute(buf, "no data! yet"); err != nil {
		return "", err
	}

	var rev plumbing.Hash
	if rev, err = working.Commit(buf.String(), &gogit.CommitOptions{
		All: true,
		Author: &object.Signature{
			Name:  commit.AuthorName,
			Email: commit.AuthorEmail,
			When:  time.Now(),
		},
	}); err != nil {
		return "", err
	}

	return rev.String(), repo.PushContext(ctx, &gogit.PushOptions{
		Auth: auth,
	})
}

func (h handler) auth(gitrepo *v1alpha1.GitRepo) (transport.AuthMethod, error) {
	if gitrepo.Spec.ClientSecretName == "" {
		return nil, errors.New("requires git secret for write access")
	}

	secret, err := h.secretCache.Get(gitrepo.Namespace, gitrepo.Spec.ClientSecretName)
	if err != nil {
		return nil, err
	}

	switch secret.Type {
	case corev1.SecretTypeBasicAuth:
		return &http.BasicAuth{
			Username: string(secret.Data[corev1.BasicAuthUsernameKey]),
			Password: string(secret.Data[corev1.BasicAuthPasswordKey]),
		}, nil
	case corev1.SecretTypeSSHAuth:
		publicKey, err := ssh.NewPublicKeys("git", secret.Data[corev1.SSHAuthPrivateKey], "")
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	}
	return nil, errors.New("invalid secret type")
}

// authFromSecret creates an Authenticator that can be given to the
// `remote` funcs, from a Kubernetes secret. If the secret doesn't
// have the right format or data, it returns an error.
func authFromSecret(secret *corev1.Secret, registry string) (authn.Authenticator, error) {
	switch secret.Type {
	case "kubernetes.io/dockerconfigjson":
		var dockerconfig struct {
			Auths map[string]authn.AuthConfig
		}
		configData := secret.Data[".dockerconfigjson"]
		if err := json.NewDecoder(bytes.NewBuffer(configData)).Decode(&dockerconfig); err != nil {
			return nil, err
		}
		auth, ok := dockerconfig.Auths[registry]
		if !ok {
			return nil, fmt.Errorf("auth for %q not found in secret %v", registry, types.NamespacedName{Name: secret.GetName(), Namespace: secret.GetNamespace()})
		}
		return authn.FromConfig(auth), nil
	default:
		return nil, fmt.Errorf("unknown secret type %q", secret.Type)
	}
}

func shouldScan(image *v1alpha1.ImageScan) bool {
	interval := image.Spec.Interval
	if interval.Seconds() == 0.0 {
		interval = metav1.Duration{
			Duration: time.Minute * 5,
		}
	}
	if image.Status.LastScanTags == nil {
		return true
	}

	if time.Now().Sub(image.Status.LastScanTime.Time) < interval.Duration {
		return false
	}
	return true
}

func latestTag(policy v1alpha1.ImagePolicyChoice, versions []string) (string, error) {
	switch {
	case policy.SemVer != nil:
		contraints, err := semver.NewConstraint(policy.SemVer.Range)
		if err != nil {
			return "", err
		}
		var latestVersion *semver.Version
		for _, version := range versions {
			if ver, err := semver.NewVersion(version); err == nil {
				if latestVersion == nil || ver.GreaterThan(latestVersion) {
					if contraints.Check(ver) {
						latestVersion = ver
					}
				}
			}
		}
		return latestVersion.Original(), nil
	case policy.Alphabetical != nil:
		var des bool
		if policy.Alphabetical.Order == "" {
			des = true
		} else {
			des = policy.Alphabetical.Order == AlphabeticalOrderDesc
		}
		var latest string
		for _, version := range versions {
			if latest == "" {
				latest = version
				continue
			}

			if version >= latest && des {
				latest = version
			}

			if version <= latest && !des {
				latest = version
			}
		}
		return latest, nil
	}
	return "", errors.New("failed to find the latest version")
}
