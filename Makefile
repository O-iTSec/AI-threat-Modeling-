.PHONY: help setup test lint scan scan-no-llm scan-basic scan-ci ci clean

ifneq ("$(wildcard .venv/bin/python)","")
PYTHON ?= .venv/bin/python
else
PYTHON ?= python
endif
EXAMPLE ?= examples/docker-compose.yml
TYPE ?= compose
FORMAT ?= both
OUTPUT ?= report
OUTPUT_DIR ?= outputs

help:
	@echo "Available targets:"
	@echo "  make setup                                 Install project + dev dependencies"
	@echo "  make lint                                  Run ruff lint + format checks"
	@echo "  make test                                  Run unit tests"
	@echo "  make ci                                    Run lint + test locally"
	@echo "  make scan EXAMPLE=... TYPE=...             Run full scan (LLM enabled)"
	@echo "  make scan-no-llm EXAMPLE=... TYPE=...      Run scan without LLM"
	@echo "  make scan-ci                               Run deterministic CI gate scan + SARIF"
	@echo "  make scan-basic                            Run compose example quickly"
	@echo "  make clean                                 Remove generated outputs"

setup:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check src/ tests/
	$(PYTHON) -m ruff format --check src/ tests/

test:
	$(PYTHON) -m pytest tests/ -v

ci: lint test

scan:
	$(PYTHON) -m src.cli $(EXAMPLE) -t $(TYPE) -f $(FORMAT) -o $(OUTPUT) --output-dir $(OUTPUT_DIR)

scan-no-llm:
	$(PYTHON) -m src.cli $(EXAMPLE) -t $(TYPE) -f $(FORMAT) -o $(OUTPUT) --output-dir $(OUTPUT_DIR) --no-llm

scan-ci:
	$(PYTHON) -m src.cli examples/docker-compose.yml -t compose --no-llm -f sarif --policy policies/ci.yml --output-dir outputs -o report

scan-basic:
	$(MAKE) scan EXAMPLE=examples/docker-compose.yml TYPE=compose

clean:
	rm -f report.pdf report.sarif
	rm -rf outputs/*
