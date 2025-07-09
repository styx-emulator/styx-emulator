BUILD_CONTEXT := ../../../../
DOCKERFILE := `pwd`/Dockerfile
TAG=trace-webapp

image:
	cp .dockerignore $(BUILD_CONTEXT)
	docker build -f $(DOCKERFILE) -t $(TAG) $(BUILD_CONTEXT)
