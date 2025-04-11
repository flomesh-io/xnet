#!make

CTR_REGISTRY ?= flomesh
CTR_TAG      ?= latest

DOCKER_BUILDX_PLATFORM ?= linux/amd64
DOCKER_BUILDX_OUTPUT ?= type=registry

VERSION ?= dev
BUILD_DATE ?= $(shell date +%Y-%m-%d-%H:%M-%Z)
GIT_SHA=$$(git rev-parse HEAD)
BUILD_DATE_VAR := github.com/flomesh-io/xnet/pkg/version.BuildDate
BUILD_VERSION_VAR := github.com/flomesh-io/xnet/pkg/version.Version
BUILD_GITCOMMIT_VAR := github.com/flomesh-io/xnet/pkg/version.GitCommit

LDFLAGS ?= "-X $(BUILD_DATE_VAR)=$(BUILD_DATE) -X $(BUILD_VERSION_VAR)=$(VERSION) -X $(BUILD_GITCOMMIT_VAR)=$(GIT_SHA) -s -w"

.PHONY: buildx-context
buildx-context:
	@if ! docker buildx ls | grep -q "^fsm"; then docker buildx create --name fsm --driver-opt network=host; fi

.PHONY: docker-build-xnet
docker-build-xnet:
	docker buildx build --builder fsm --platform=$(DOCKER_BUILDX_PLATFORM) -o $(DOCKER_BUILDX_OUTPUT) -t $(CTR_REGISTRY)/xnet:$(CTR_TAG) -f dockerfiles/Dockerfile --build-arg LDFLAGS=$(LDFLAGS) .

.PHONY: docker-build-xnet-ubuntu-20.04
docker-build-xnet-ubuntu-20.04:
	docker buildx build --builder fsm --platform=$(DOCKER_BUILDX_PLATFORM) -o $(DOCKER_BUILDX_OUTPUT) -t $(CTR_REGISTRY)/xnet:ubuntu-20.04-$(CTR_TAG) -f dockerfiles/Dockerfile.ubuntu.20.04 --build-arg LDFLAGS=$(LDFLAGS) .

.PHONY: docker-build-xnet-ubuntu-22.04
docker-build-xnet-ubuntu-22.04:
	docker buildx build --builder fsm --platform=$(DOCKER_BUILDX_PLATFORM) -o $(DOCKER_BUILDX_OUTPUT) -t $(CTR_REGISTRY)/xnet:ubuntu-22.04-$(CTR_TAG) -f dockerfiles/Dockerfile.ubuntu.22.04 --build-arg LDFLAGS=$(LDFLAGS) .

.PHONY: docker-build-xnet-ubuntu-24.04
docker-build-xnet-ubuntu-24.04:
	docker buildx build --builder fsm --platform=$(DOCKER_BUILDX_PLATFORM) -o $(DOCKER_BUILDX_OUTPUT) -t $(CTR_REGISTRY)/xnet:ubuntu-24.04-$(CTR_TAG) -f dockerfiles/Dockerfile.ubuntu.24.04 --build-arg LDFLAGS=$(LDFLAGS) .

.PHONY: docker-build-xnet-bclinux-openeuler-22.03
docker-build-xnet-bclinux-openeuler-22.03:
docker-build-xnet-bclinux-openeuler-22.03:
	docker buildx build --builder fsm --platform=$(DOCKER_BUILDX_PLATFORM) -o $(DOCKER_BUILDX_OUTPUT) -t $(CTR_REGISTRY)/xnet:openeuler-22.03-$(CTR_TAG) -f dockerfiles/Dockerfile.openeuler.22.03 --build-arg LDFLAGS=$(LDFLAGS) .

TARGETS = xnet xnet-ubuntu-20.04 xnet-ubuntu-22.04 xnet-ubuntu-24.04
DOCKER_TARGETS = $(addprefix docker-build-, $(TARGETS))
IMAGE_TARGETS = xnet- xnet-ubuntu-20.04- xnet-ubuntu-22.04- xnet-ubuntu-24.04-

$(foreach target,$(TARGETS) ,$(eval docker-build-$(target): buildx-context))

.PHONY: docker-build
docker-build: $(DOCKER_TARGETS)

.PHONY: docker-build-cross
docker-build-cross: DOCKER_BUILDX_PLATFORM=linux/amd64,linux/arm64
docker-build-cross: docker-build

.PHONY: trivy-ci-setup
trivy-ci-setup:
	wget https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_Linux-64bit.tar.gz
	tar zxvf trivy_0.59.1_Linux-64bit.tar.gz
	echo $$(pwd) >> $(GITHUB_PATH)

# Show all vulnerabilities in logs
trivy-scan-verbose-%: TAG_PREFIX=$(@:trivy-scan-verbose-xnet-%=%)
trivy-scan-verbose-%:
	trivy image --scanners vuln,secret \
	  --pkg-types os \
	  --db-repository aquasec/trivy-db:2 \
	  "$(CTR_REGISTRY)/xnet:$(TAG_PREFIX)$(CTR_TAG)"

# Exit if vulnerability exists
trivy-scan-fail-%: TAG_PREFIX=$(@:trivy-scan-fail-xnet-%=%)
trivy-scan-fail-%:
	trivy image --exit-code 1 \
	  --ignore-unfixed \
	  --severity MEDIUM,HIGH,CRITICAL \
	  --dependency-tree \
	  --scanners vuln,secret \
	  --pkg-types os \
	  --db-repository aquasec/trivy-db:2 \
	  "$(CTR_REGISTRY)/xnet:$(TAG_PREFIX)$(CTR_TAG)"

.PHONY: trivy-scan-images trivy-scan-images-fail trivy-scan-images-verbose
trivy-scan-images-verbose: $(addprefix trivy-scan-verbose-, $(IMAGE_TARGETS))
trivy-scan-images-fail: $(addprefix trivy-scan-fail-, $(IMAGE_TARGETS))
trivy-scan-images: trivy-scan-images-verbose trivy-scan-images-fail

.PHONY: release
VERSION_REGEXP := ^v[0-9]+\.[0-9]+\.[0-9]+(\-(alpha|beta|rc)\.[0-9]+)?$
release: ## Create a release tag, push to git repository and trigger the release workflow.
ifeq (,$(RELEASE_VERSION))
	$(error "RELEASE_VERSION must be set to tag HEAD")
endif
	git tag --sign --message "fsm $(RELEASE_VERSION)" $(RELEASE_VERSION)
	git verify-tag --verbose $(RELEASE_VERSION)
	git push origin --tags
