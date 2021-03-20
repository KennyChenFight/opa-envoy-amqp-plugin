IMAGE_NAME := opa-envoy-amqp
REPOSITORY := kennychenfight/opa-enovy-amqp
VERSION := v1

.PHONY: all
all: image

.PHONY: image
image: build-image push-image

.PHONY: build
build:
	@echo "Building the $(IMAGE_NAME) binary..."
	go build -o build/bin/$(IMAGE_NAME) ./cmd/

.PHONY: build-linux
build-linux:
	@echo "Building the $(REPOSITORY) binary for Docker (linux)..."
	@GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/bin/$(IMAGE_NAME) ./cmd/

.PHONY: build-image
build-image: build-linux
	@echo "Building the docker image: $(REPOSITORY)..."
	docker build --no-cache -t $(REPOSITORY):latest -t $(REPOSITORY):$(VERSION) .

.PHONY: push-image
push-image: build-image
	@echo "Pushing the docker image for $(REPOSITORY)/$(VERSION) and $(REPOSITORY):latest..."
	docker push $(REPOSITORY):$(VERSION)
    docker push $(REPOSITORY):latest

