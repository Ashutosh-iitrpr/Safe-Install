.PHONY: build test test-docker
build:
	docker build -t safeinstall-sandbox:test safeinstall/sandbox
	docker build -t safeinstall-gateway:test safeinstall/gateway

test:
	pytest -q

test-docker: build
	pytest -m docker -q
