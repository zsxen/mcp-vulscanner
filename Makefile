PYTHON := python3
UV := env UV_CACHE_DIR=$(CURDIR)/.uv-cache uv

.PHONY: test tree

test:
	$(UV) run $(PYTHON) -m unittest discover -s tests -v

tree:
	find . -maxdepth 4 \
		-not -path './.git/*' \
		-not -path './.uv-cache/*' \
		| sort
