#!make

CTR_REGISTRY ?= cybwan
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
	docker buildx build --builder fsm --platform=$(DOCKER_BUILDX_PLATFORM) -o $(DOCKER_BUILDX_OUTPUT) -t $(CTR_REGISTRY)/xnet:$(CTR_TAG) -f Dockerfile --build-arg LDFLAGS=$(LDFLAGS) .

TARGETS = xnet
DOCKER_TARGETS = $(addprefix docker-build-, $(TARGETS))

$(foreach target,$(TARGETS) ,$(eval docker-build-$(target): buildx-context))

.PHONY: docker-build
docker-build: $(DOCKER_TARGETS)

.PHONY: docker-build-cross
docker-build-cross: DOCKER_BUILDX_PLATFORM=linux/amd64,linux/arm64
docker-build-cross: docker-build

.PHONY: release
VERSION_REGEXP := ^v[0-9]+\.[0-9]+\.[0-9]+(\-(alpha|beta|rc)\.[0-9]+)?$
release: ## Create a release tag, push to git repository and trigger the release workflow.
ifeq (,$(RELEASE_VERSION))
	$(error "RELEASE_VERSION must be set to tag HEAD")
endif
	git tag --sign --message "fsm $(RELEASE_VERSION)" $(RELEASE_VERSION)
	git verify-tag --verbose $(RELEASE_VERSION)
	git push origin --tags
