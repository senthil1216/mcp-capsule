.PHONY: help install test bench demo clean

help:
	@echo "Capsule — a capability gateway for MCP tools"
	@echo ""
	@echo "  make install   editable install with dev + mcp extras"
	@echo "  make test      run the test suite (pytest -q)"
	@echo "  make bench     run the attack corpus (unsafe + safe) -> bench/REPORT.md"
	@echo "  make demo      run the end-to-end demo script"
	@echo "  make clean     remove caches and runtime artifacts"

install:
	pip install -e ".[dev,mcp]"

test:
	pytest -q

bench:
	python -m bench.runner --mode both
	@echo ""
	@echo "Report: bench/REPORT.md"

demo:
	bash docs/demo.sh

clean:
	rm -rf .pytest_cache **/__pycache__ audit.log \
	       demo/pending_approvals.jsonl demo/fake_github_events.jsonl \
	       demo/taint_store.jsonl bench/.honeytokens
