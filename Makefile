.DEFAULT_GOAL := help

.PHONY: help install dev lint format typecheck test test-cov clean build

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install package
	pip install -e .

dev: ## Install with dev dependencies
	pip install -e ".[dev]"

lint: ## Run linter (ruff)
	ruff check src/ tests/

format: ## Format code (black)
	black src/ tests/

format-check: ## Check code formatting
	black --check src/ tests/

typecheck: ## Run type checker (mypy)
	mypy src/auditor/ --ignore-missing-imports

test: ## Run tests
	python -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	python -m pytest tests/ -v --cov=auditor --cov-report=term-missing --cov-report=html

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: ## Build distribution package
	python -m build

ci: lint format-check typecheck test ## Run all CI checks
