.PHONY: build test
build:
	docker build -t safeinstall-sandbox:test safeinstall/sandbox
	docker build -t safeinstall-gateway:test safeinstall/gateway

test:
	pytest -q
