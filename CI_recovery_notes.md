# mcp-vulscanner CI recovery

## What this fixes
- missing `data/corpus/targets.json`
- missing `data/corpus/ground-truth.json`
- missing `data/fixtures/eval/sample-results.json`
- missing static fixtures under `data/fixtures/static/{js,python}/{vulnerable,patched}`
- missing stdio/HTTP replay fixtures under `data/fixtures/dynamic/`

## Use
From the repository root:

```bash
bash /path/to/setup_ci_test_assets.sh
UV_CACHE_DIR=.uv-cache uv run python -m unittest discover -s tests -v
git add data/corpus data/fixtures
git commit -m "Add seed corpus and fixture files for CI"
git push
```

## Files created
- `data/corpus/targets.json`
- `data/corpus/ground-truth.json`
- `data/fixtures/eval/sample-results.json`
- `data/fixtures/static/js/vulnerable/index.js`
- `data/fixtures/static/js/patched/index.js`
- `data/fixtures/static/python/vulnerable/server.py`
- `data/fixtures/static/python/patched/server.py`
- `data/fixtures/dynamic/stdio_vulnerable_server.py`
- `data/fixtures/dynamic/stdio_guarded_server.py`
- `data/fixtures/dynamic/stdio_safe_server.py`
- `data/fixtures/dynamic/paper_stdio_vulnerable_server.py`
- `data/fixtures/dynamic/http_header_ssrf_server.py`
- `data/fixtures/dynamic/http_base_url_ssrf_server.py`
- `data/fixtures/dynamic/http_redirect_ssrf_server.py`
