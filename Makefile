.PHONY: help install test test-docker bench demo clean sandbox-image

help:
	@echo "Capsule — a capability gateway for MCP tools"
	@echo ""
	@echo "  make install        editable install with dev + mcp + sandbox extras"
	@echo "  make test           run the base suite (runtime-free; docker tests deselected)"
	@echo "  make test-docker    run the run_command sandbox integration tests (needs docker)"
	@echo "  make sandbox-image  build the run_command sandbox image (Milestone D)"
	@echo "  make bench          run the attack corpus (unsafe + safe) -> bench/REPORT.md"
	@echo "  make demo           run the end-to-end demo script"
	@echo "  make clean          remove caches and runtime artifacts"

install:
	pip install -e ".[dev,mcp,sandbox]"

sandbox-image:
	docker build -t capsule-sandbox:latest sandbox/

test:
	pytest -q

test-docker:
	pytest -q -m docker

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
