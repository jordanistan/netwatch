# Contributing to NetWatch

Thank you for your interest in contributing to NetWatch! This guide will help you get started with contributing to the project.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to maintain a welcoming and inclusive environment for all contributors.

## Getting Started

1. **Fork the Repository**
   ```bash
   # Clone your fork
   git clone https://github.com/yourusername/netwatch.git
   cd netwatch
   
   # Add upstream remote
   git remote add upstream https://github.com/original/netwatch.git
   ```

2. **Set Up Development Environment**
   ```bash
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate  # Unix
   # or
   .\venv\Scripts\activate  # Windows
   
   # Install dependencies
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature
   # or
   git checkout -b fix/your-bugfix
   ```

## Development Guidelines

### Code Style

1. **Python Standards**
   - Follow PEP 8
   - Use type hints
   - Write docstrings
   - Keep functions focused

2. **Example**
   ```python
   from typing import List, Dict

   def process_devices(devices: List[Dict]) -> Dict:
       """
       Process device information.

       Args:
           devices: List of device dictionaries

       Returns:
           Dict containing processed data
       """
       result = {}
       for device in devices:
           # Process device
           pass
       return result
   ```

### Testing

1. **Writing Tests**
   ```python
   import pytest
   from netwatch.scanner import NetworkScanner

   def test_device_discovery():
       scanner = NetworkScanner()
       devices = scanner.scan_devices("eth0")
       assert isinstance(devices, list)
       assert len(devices) > 0
   ```

2. **Running Tests**
   ```bash
   # Run all tests
   pytest

   # Run specific test
   pytest tests/test_scanner.py

   # Run with coverage
   pytest --cov=netwatch
   ```

### Documentation

1. **Code Documentation**
   ```python
   class DeviceMonitor:
       """
       Network device monitoring class.

       Attributes:
           interface: Network interface
           capture_dir: Directory for PCAP files
       """

       def start_monitoring(self, target: str) -> None:
           """
           Start monitoring a target device.

           Args:
               target: IP address to monitor
           """
           pass
   ```

2. **Project Documentation**
   - Update README.md
   - Add docstrings
   - Create examples
   - Document API changes

## Pull Request Process

1. **Before Submitting**
   - Run tests
   - Update documentation
   - Follow style guide
   - Add test cases

2. **Submitting PR**
   ```bash
   # Update branch
   git fetch upstream
   git rebase upstream/main

   # Push changes
   git push origin feature/your-feature
   ```

3. **PR Template**
   ```markdown
   ## Description
   Brief description of changes

   ## Type of Change
   - [ ] Bug fix
   - [ ] New feature
   - [ ] Documentation update
   - [ ] Performance improvement

   ## Testing
   Description of testing performed

   ## Screenshots
   If applicable
   ```

## Development Tools

### Linting

```bash
# Run flake8
flake8 netwatch

# Run mypy
mypy netwatch

# Run black
black netwatch
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v3.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
```

### CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
      - name: Run tests
        run: |
          pip install -r requirements.txt
          pytest
```

## Feature Development

### Planning

1. **Feature Proposal**
   ```markdown
   ## Feature: Network Traffic Analysis
   
   ### Description
   Add capability to analyze network traffic patterns
   
   ### Requirements
   - PCAP parsing
   - Pattern detection
   - Visualization
   
   ### Implementation Plan
   1. Add PCAP reader
   2. Implement analysis
   3. Create visualizations
   ```

2. **Design Document**
   ```markdown
   ## Design: Traffic Analysis
   
   ### Components
   - PCAPReader
   - TrafficAnalyzer
   - VisualizationEngine
   
   ### Data Flow
   PCAP -> Analysis -> Visualization
   
   ### API Design
   [API details]
   ```

### Implementation

1. **Code Structure**
   ```python
   # traffic_analyzer.py
   class TrafficAnalyzer:
       def __init__(self):
           self.patterns = []
   
       def analyze(self, pcap_file):
           # Implementation
           pass
   ```

2. **Testing Strategy**
   ```python
   # test_analyzer.py
   class TestTrafficAnalyzer:
       def setup_method(self):
           self.analyzer = TrafficAnalyzer()
   
       def test_pattern_detection(self):
           # Test implementation
           pass
   ```

## Bug Fixes

### Reporting Bugs

1. **Issue Template**
   ```markdown
   ## Bug Report
   
   ### Description
   Clear description of the bug
   
   ### Steps to Reproduce
   1. Step 1
   2. Step 2
   3. Step 3
   
   ### Expected Behavior
   What should happen
   
   ### Actual Behavior
   What actually happens
   
   ### System Information
   - OS:
   - Python version:
   - NetWatch version:
   ```

2. **Debug Information**
   ```python
   # Enable debug logging
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

### Fixing Bugs

1. **Investigation**
   ```python
   def investigate_bug():
       # Add debug logging
       logger.debug("Investigating bug")
       
       # Add assertions
       assert condition, "Bug condition"
       
       # Test fix
       test_bug_fix()
   ```

2. **Verification**
   ```python
   def verify_fix():
       # Run test cases
       run_tests()
       
       # Check edge cases
       test_edge_cases()
       
       # Verify performance
       benchmark_fix()
   ```

## Release Process

### Version Control

1. **Semantic Versioning**
   ```text
   MAJOR.MINOR.PATCH
   1.0.0 -> Initial release
   1.1.0 -> New feature
   1.1.1 -> Bug fix
   ```

2. **Release Notes**
   ```markdown
   # Release Notes v1.1.0
   
   ## New Features
   - Feature A
   - Feature B
   
   ## Bug Fixes
   - Fix X
   - Fix Y
   
   ## Breaking Changes
   - Change Z
   ```

### Publishing

1. **Package Release**
   ```bash
   # Update version
   bump2version minor
   
   # Build package
   python setup.py sdist bdist_wheel
   
   # Upload to PyPI
   twine upload dist/*
   ```

2. **Documentation Update**
   ```bash
   # Generate docs
   sphinx-build -b html docs/ docs/_build/html
   
   # Deploy docs
   ./deploy_docs.sh
   ```

## Community

### Communication

- GitHub Issues
- Discord Server
- Mailing List
- Community Meetings

### Recognition

- Contributors list
- Hall of Fame
- Feature credits
- Bug bounties

## Resources

### Documentation

- [Development Guide](docs/development.md)
- [API Reference](docs/api-reference.md)
- [Testing Guide](docs/testing.md)

### Tools

- IDE Setup
- Development Tools
- Testing Framework
- CI/CD Pipeline
