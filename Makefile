PYTHON := python3
UV := env UV_CACHE_DIR=$(CURDIR)/.uv-cache uv

.PHONY: test tree paper-tables

test:
	$(UV) run $(PYTHON) -m unittest discover -s tests -v

paper-tables:
	$(UV) run $(PYTHON) -m mcp_vulscanner.eval.render_tables \
		--input data/fixtures/eval/sample-results.json \
		--output-dir paper/generated

tree:
	find . -maxdepth 4 \
		-not -path './.git/*' \
		-not -path './.uv-cache/*' \
		| sort
