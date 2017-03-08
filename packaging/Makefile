.PHONY: docker-push

VERSION  ?= $(shell git rev-parse HEAD)
REGISTRY ?= registry-write.opensource.zalan.do/pathfinder
IMAGE    ?= $(REGISTRY)/skipper:$(VERSION)
COMMIT_HASH =     $(shell git rev-parse --short HEAD)

default: docker-build

skipper:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT_HASH)" github.com/zalando/skipper/cmd/skipper

eskip:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT_HASH)" github.com/zalando/skipper/cmd/eskip

clean:
	rm -f skipper eskip

docker-build: clean skipper eskip
	docker build -t $(IMAGE) .

docker-push:
	docker push $(IMAGE)
