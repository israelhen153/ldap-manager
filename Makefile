.PHONY: help install lint typecheck security test test-quick coverage ci clean nuke

VENV_DIR  ?= .venv
PYTHON    ?= python3
PIP       := $(VENV_DIR)/bin/pip
PYTEST    := $(VENV_DIR)/bin/pytest
RUFF      := $(VENV_DIR)/bin/ruff
MYPY      := $(VENV_DIR)/bin/mypy
BANDIT    := $(VENV_DIR)/bin/bandit

# Marker file — touched after successful install
INSTALLED := $(VENV_DIR)/.installed

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

$(VENV_DIR)/bin/activate:
	$(PYTHON) -m venv $(VENV_DIR)
	$(PIP) install --upgrade pip setuptools wheel

$(INSTALLED): $(VENV_DIR)/bin/activate pyproject.toml
	$(PIP) install -e ".[dev]"
	@touch $(INSTALLED)

install: $(INSTALLED) ## Create venv and install package + dev deps (skips if up to date)

lint: $(INSTALLED) ## Run ruff linter + formatter check
	$(RUFF) check ldap_manager/ tests/
	$(RUFF) format --check ldap_manager/ tests/

lint-fix: $(INSTALLED) ## Auto-fix lint issues
	$(RUFF) check --fix ldap_manager/ tests/
	$(RUFF) format ldap_manager/ tests/

typecheck: $(INSTALLED) ## Run mypy type checking
	$(MYPY) ldap_manager/

security: $(INSTALLED) ## Run bandit security scan
	$(BANDIT) -r ldap_manager/ -c pyproject.toml -q

test: $(INSTALLED) ## Run full test suite with coverage
	$(PYTEST)

test-quick: $(INSTALLED) ## Run tests without coverage (faster)
	$(PYTEST) --no-cov -x -q

coverage: test ## Generate coverage report and check threshold
	@echo ""
	@echo "HTML report: htmlcov/index.html"
	@echo "XML report:  coverage.xml"

ci: lint typecheck security test ## Run all CI checks (lint → types → security → tests)
	@echo ""
	@echo "All checks passed."

clean: ## Remove build artifacts (keep venv)
	rm -rf build/ dist/ *.egg-info htmlcov/ .mypy_cache/ .ruff_cache/
	rm -f coverage.xml test-results.xml .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

nuke: clean ## Remove everything including venv
	rm -rf $(VENV_DIR)
