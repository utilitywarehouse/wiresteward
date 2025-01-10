.PHONY: generate-mocks
generate-mocks:
	mkdir -p mocks
	mockgen -source=ping.go -destination=mocks/mock_ping.go -package=mocks

.PHONY: release
release:
	@sd '(default\s*=\s*").+(" # MAKE_RELEASE_MARKER)' '$${1}$(VERSION)$${2}' $$(rg -l '# MAKE_RELEASE_MARKER' terraform/)
	@git add -- terraform/
	@git commit -m "Release $(VERSION)"
	@sd '(default\s*=\s*").+(" # MAKE_RELEASE_MARKER)' '$${1}latest$${2}' $$(rg -l '# MAKE_RELEASE_MARKER' terraform/)
	@git add -- terraform/
	@git commit -m "Clean up release $(VERSION)"
