.PHONY: help install install-dev test test-cov lint format clean setup check-deps run-example

# Default target
help:
	@echo "Offensive Security Automation Toolkit - Development Commands"
	@echo ""
	@echo "Available commands:"
	@echo "  install      - Install production dependencies"
	@echo "  install-dev  - Install development dependencies"
	@echo "  test         - Run all tests"
	@echo "  test-cov     - Run tests with coverage"
	@echo "  lint         - Run linting checks"
	@echo "  format       - Format code with black and isort"
	@echo "  clean        - Clean up generated files"
	@echo "  setup        - Initial setup (install + create config)"
	@echo "  check-deps   - Check for security vulnerabilities"
	@echo "  run-example  - Run example penetration test"
	@echo "  docs         - Build documentation"
	@echo "  dist         - Build distribution package"

# Installation
install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

# Testing
test:
	python3 -m pytest tests/ -v

test-cov:
	python3 -m pytest tests/ --cov=core --cov=cli --cov-report=html --cov-report=term

# Code quality
lint:
	flake8 core/ cli/ tests/
	mypy core/ cli/
	bandit -r core/ cli/

format:
	black core/ cli/ tests/
	isort core/ cli/ tests/

# Security
check-deps:
	safety check

# Documentation
docs:
	cd docs && make html

# Cleanup
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ .pytest_cache/ .coverage htmlcov/
	rm -rf outputs/*.json outputs/*.md outputs/*.pdf

# Setup
setup: install-dev
	@echo "Setting up Offsec Toolkit..."
	@if [ ! -f config/settings.json ]; then \
		echo "Creating configuration file..."; \
		cp config/settings.json.example config/settings.json 2>/dev/null || \
		echo '{"general": {"output_directory": "outputs"}}' > config/settings.json; \
	fi
	@echo "Setup complete!"

# Distribution
dist: clean
	python3 setup.py sdist bdist_wheel

# Example run
run-example:
	@echo "Running example penetration test..."
	@echo "Target: 192.168.1.10 (Metasploitable 2)"
	@echo "Attacker: 192.168.1.16"
	@echo ""
	python3 -m cli.main --target 192.168.1.10 --attacker-ip 192.168.1.16 --walkthrough --services http,ftp,ssh --no-confirm

# Quick test
quick-test:
	@echo "Running quick functionality test..."
	python3 -m pytest tests/test_exploit_scripts.py::TestExploitScripts::test_ftp_exploit_script -v

# Development workflow
dev-setup: setup
	@echo "Development environment ready!"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make lint' to check code quality"
	@echo "Run 'make format' to format code"

# CI/CD
ci: lint test check-deps
	@echo "CI checks passed!"

# Release preparation
release-prep: clean test-cov lint check-deps docs
	@echo "Release preparation complete!"
	@echo "Run 'make dist' to build distribution"

# Help for specific components
help-ftp:
	@echo "FTP Exploitation:"
	@echo "  python3 core/exploit/ftp_exploit.py --help"

help-http:
	@echo "HTTP Exploitation:"
	@echo "  python3 core/exploit/http_exploit.py --help"

help-cli:
	@echo "CLI Usage:"
	@echo "  python3 -m cli.main --help"

# Monitoring
status:
	@echo "Checking project status..."
	@echo "Python version: $(shell python3 --version)"
	@echo "Dependencies: $(shell pip list | grep -E "(nmap|jinja2|weasyprint)" | wc -l) installed"
	@echo "Tests: $(shell find tests/ -name "*.py" | wc -l) test files"
	@echo "Exploit scripts: $(shell find core/exploit/ -name "*.py" | wc -l) scripts"
	@echo "Service modules: $(shell find core/services/ -name "*.py" | wc -l) modules" 