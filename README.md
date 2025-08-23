# C/C++ Vulnerability Analyzer
A comprehensive static analysis tool for detecting security vulnerabilities in C/C++ source code using both AI-powered analysis and rule-based heuristics.

## Features
- **Hybrid Analysis**: Combines AI-powered analysis (Phi-4 model) with rule-based vulnerability detection
- **Offline Operation**: Works completely offline after initial setup
- **Multiple Output Formats**: Text and JSON reports
- **Comprehensive Coverage**: Detects buffer overflows, memory leaks, format string vulnerabilities, and more
- **Smart Chunking**: Intelligently splits large files for efficient analysis
- **Severity Classification**: Categorizes vulnerabilities by severity (Critical/High/Medium/Low)
- **Fix Suggestions**: Provides actionable remediation advice
- **CLI Interface**: Easy-to-use command-line interface

##  Architecture
The tool follows a modular architecture with clear separation of concerns:

```
vuln-analyzer/
├── cli.py                     # CLI entry point and orchestration
├── models/
│   └── phi-4/                  # AI model files (after setup)
├── src/
│   ├── analysis/
│   │   ├── chunker.py      # AI model integration (Phi-4)
│   │   ├── extractor.py          # Code chunking and preprocessing
│   │   ├── heuristics.py        # Vulnerability pattern extraction
│   │   └── llm_backend.py       # Rule-based analysis engine
│   └── report/
│       └── formatter.py        # Report generation and formatting
├── tests/
│    └── data/                   # Test files
├── README.md
├── Report.md
├── setup_model.py              # Model setup and download script
├── test_offline.py
└── test_phi4_load.py

```

### Core Components

1. **VulnerabilityAnalyzer** (`cli.py`): Main orchestrator that coordinates all components
2. **ONNXLLMBackend** (`llm_backend.py`): AI-powered analysis using Microsoft's Phi-4 model
3. **CodeChunker** (`chunker.py`): Intelligent code segmentation for efficient processing
4. **HeuristicAnalyzer** (`heuristics.py`): Rule-based vulnerability detection
5. **VulnerabilityExtractor** (`extractor.py`): Pattern matching and vulnerability extraction
6. **ReportFormatter** (`formatter.py`): Multi-format report generation

## Offline Operation Guarantee

This tool operates completely offline after initial setup:
- **One-time setup requires internet** (run `setup_model.py`)
- **After setup, NO internet connection is needed**
- **All analysis happens locally on your machine**
- **No data is ever sent to external servers**

## Installation & Setup

### Prerequisites

- Python 3.8 or higher
- 8GB RAM minimum (16GB recommended for Phi-4)
- 10GB disk space for model files
- Internet connection (only for initial setup)

### Step 1: Clone Repository
```bash
git clone https://github.com/danielnisanov/vuln-analyzer.git
cd vuln-analyzer
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run Setup Script (Requires Internet)
```bash
# This downloads and prepares model files for offline use
python setup_model.py
```

### Step 4: Verify Offline Operation
```bash
# Test that the tool works without internet
python test_offline.py
```

**After setup is complete, the tool operates entirely offline.**

## Offline Operation

Once the setup is complete, the tool requires **NO internet connection**. All analysis is performed locally using:
- Pre-downloaded Phi-4 ONNX model
- Local tokenizer files  
- Rule-based heuristics as fallback

To ensure offline operation:
1. Run `setup_model.py` once with internet
2. All model files are stored in `./models/phi-4/`
3. The tool will never attempt to download files during normal operation

## Quick Start

### Basic Usage

```bash
# Analyze a single file
python cli.py vulnerable_code.c

# Verbose output with fixes
python cli.py --verbose --fixes vulnerable_code.c

# Generate JSON report
python cli.py --format json --output report.json source.cpp

# Rule-based analysis only (no AI model required)
python cli.py --no-model vulnerable_code.c

```

### Advanced Usage

```bash
# Custom model path
python cli.py --model ./custom_model input.c

# Configuration file
python cli.py --config config.json input.c
```

## Supported Vulnerabilities

The analyzer detects various vulnerability types:

### Critical Severity
- **Buffer Overflows**: `gets()`, unsafe `strcpy()`, `strcat()`, `sprintf()`
- **Command Injection**: `system()`, `exec()`, `popen()` with user input

### High Severity
- **Use After Free**: Memory access after deallocation
- **Format String**: Unvalidated format strings in `printf()` family
- **Buffer Overflows**: Unsafe string operations

### Medium Severity
- **Memory Leaks**: Missing `free()` calls
- **Null Pointer Dereference**: Unchecked pointer access
- **Race Conditions**: Unsafe threading operations
- **Resource Management**: File operations without error checking

### Low Severity
- **Integer Overflow**: Potential arithmetic overflows
- **Weak Random**: `rand()` without proper seeding

## Output Formats

### Text Format (Default)
```
=== Vulnerability Analysis Report ===
File: vulnerable_code.c
Analysis Date: 2024-01-15 10:30:45

Line 15: [CRITICAL] Buffer Overflow - gets() function is unsafe and deprecated
Line 23: [HIGH] Use After Free - Variable 'ptr' used after free
Line 35: [MEDIUM] Memory Leak - malloc/calloc without corresponding free

=== Summary ===
Total vulnerabilities: 3
Critical: 1, High: 1, Medium: 1, Low: 0
Risk Score: 21
```

### JSON Format
```json
{
  "filename": "vulnerable_code.c",
  "vulnerabilities": [
    {
      "line": 15,
      "severity": "CRITICAL",
      "type": "Buffer Overflow",
      "description": "gets() function is unsafe and deprecated",
      "cwe": "CWE-120",
      "suggested_fix": "Replace gets() with fgets() and specify buffer size"
    }
  ],
  "statistics": {
    "total_vulnerabilities": 3,
    "risk_score": 21
  }
}
```

## Configuration

Create a `config.json` file for advanced configuration:

```json
{
  "analysis": {
    "max_chunk_size": 3000,
    "enable_llm": true,
    "confidence_threshold": 0.7
  },
  "output": {
    "include_context": true,
    "max_context_lines": 3
  },
  "vulnerabilities": {
    "ignore_patterns": ["test_", "debug_"],
    "severity_weights": {
      "CRITICAL": 10,
      "HIGH": 7,
      "MEDIUM": 4,
      "LOW": 1
    }
  }
}
```

## Troubleshooting

### Model Loading Issues
```bash
# Check if model files exist
ls -la models/phi-4/

# Test offline capability
python test_offline.py

# Use rule-based analysis only
python cli.py --no-model file.c
```

### Performance Optimization
- Use `--no-model` for faster analysis on large codebases
- Adjust chunk size in configuration for memory optimization
- Use JSON output format for programmatic processing

### Common Issues

1. **"Tokenizer not found"**: Run `python setup_model.py` first
2. **"ONNX model not available"**: The tool works with rule-based analysis; download ONNX files for AI features
3. **Out of memory**: Reduce chunk size or use `--no-model` flag

## Exit Codes

The tool returns different exit codes based on findings:

- `0`: No vulnerabilities found
- `1`: Low/Medium vulnerabilities found
- `2`: High severity vulnerabilities found
- `3`: Critical vulnerabilities found
- `4`: Analysis error occurred


## Acknowledgments

- Microsoft for the Phi-4 model
- ONNX Runtime team for efficient inference
- Security research community for vulnerability patterns

## References

- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Microsoft Phi-4 Model](https://huggingface.co/microsoft/phi-4)
