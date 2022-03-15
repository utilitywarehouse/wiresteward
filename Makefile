.PHONY: generate-mocks
generate-mocks:
	mkdir -p mocks
	mockgen -source=ping.go -destination=mocks/mock_ping.go -package=mocks
