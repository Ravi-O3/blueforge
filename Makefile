# BlueForge developer shortcuts. Run `make help` to list targets.
.PHONY: help install lint format test cover run clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Install runtime + dev dependencies and the package (editable)
	pip install -r requirements-dev.txt
	pip install -e .

lint:  ## Run ruff + mypy
	ruff check src tests
	mypy src

format:  ## Auto-format with ruff
	ruff format src tests
	ruff check --fix src tests

test:  ## Run the test suite
	pytest

cover:  ## Run tests with coverage report
	pytest --cov=blueforge --cov-report=html

run:  ## Show CLI help
	blueforge --help

clean:  ## Remove caches and build artifacts
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
