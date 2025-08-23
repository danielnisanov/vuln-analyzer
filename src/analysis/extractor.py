"""
Vulnerability Extractor
Parses LLM outputs and extracts structured vulnerability information
"""
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
    line: int
    severity: str
    type: str
    description: str
    context: str = ""
    confidence: float = 1.0
    cwe: str = ""
    suggested_fix: str = ""

class VulnerabilityExtractor:
    """
    Extracts and structures vulnerability information from various sources
    """

    def __init__(self):
        """Initialize the extractor with parsing patterns"""

        # Pattern for parsing LLM output format: "Line X: [SEVERITY] Type - Description"
        self.llm_pattern = re.compile(
            r'Line\s+(\d+):\s*\[(\w+)\]\s*([^-]+?)\s*-\s*(.+)',
            re.IGNORECASE | re.MULTILINE
        )

        # Alternative patterns for different output formats
        self.alt_patterns = [
            re.compile(r'(\d+):\s*(\w+)\s*:\s*(.+)', re.IGNORECASE),
            re.compile(r'Line\s+(\d+):\s*(.+)', re.IGNORECASE)
        ]

        # Severity normalization mapping
        self.severity_mapping = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'med': 'MEDIUM',
            'low': 'LOW',
            'info': 'LOW',
            'warning': 'MEDIUM',
            'error': 'HIGH'
        }

        # Vulnerability type patterns for classification
        self.vuln_type_patterns = {
            'Buffer Overflow': [
                r'buffer\s+overflow', r'buffer\s+overrun', r'bounds\s+check',
                r'gets\(\)', r'strcpy', r'strcat', r'sprintf'
            ],
            'Use After Free': [
                r'use\s+after\s+free', r'dangling\s+pointer', r'freed\s+memory'
            ],
            'Memory Leak': [
                r'memory\s+leak', r'missing\s+free', r'malloc.*free'
            ],
            'Format String': [
                r'format\s+string', r'printf.*user', r'format\s+specifier'
            ],
            'Integer Overflow': [
                r'integer\s+overflow', r'arithmetic\s+overflow', r'signed\s+integer'
            ],
            'Null Pointer Dereference': [
                r'null\s+pointer', r'dereference', r'null\s+check'
            ],
            'Command Injection': [
                r'command\s+injection', r'system\(\)', r'shell\s+injection'
            ],
            'Race Condition': [
                r'race\s+condition', r'thread\s+safety', r'concurrent\s+access'
            ]
        }

    def parse_llm_output(self, llm_output: str, line_offset: int = 0) -> List[Dict[str, Any]]:
        """
        Parse LLM output into structured vulnerability data

        Args:
            llm_output (str): Raw output from LLM
            line_offset (int): Line number offset for chunks

        Returns:
            List[Dict]: Structured vulnerability data
        """
        vulnerabilities = []

        if not llm_output or "No obvious vulnerabilities detected" in llm_output:
            return vulnerabilities

        # Try main pattern first
        matches = self.llm_pattern.findall(llm_output)

        for match in matches:
            line_num, severity, vuln_type, description = match

            vuln = {
                'line': int(line_num) + line_offset,
                'severity': self._normalize_severity(severity.strip()),
                'type': vuln_type.strip(),
                'description': description.strip(),
                'source': 'llm'
            }

            vulnerabilities.append(vuln)

        # If no matches with main pattern, try alternative patterns
        if not vulnerabilities:
            vulnerabilities.extend(self._try_alternative_patterns(llm_output, line_offset))

        return vulnerabilities

    def _try_alternative_patterns(self, text: str, line_offset: int) -> List[Dict[str, Any]]:
        """Try alternative parsing patterns"""
        vulnerabilities = []

        # Try each alternative pattern
        for pattern in self.alt_patterns:
            matches = pattern.findall(text)
            for match in matches:
                if len(match) == 3:  # Line, severity, description
                    line_num, severity, description = match
                    vuln = {
                        'line': int(line_num) + line_offset,
                        'severity': self._normalize_severity(severity),
                        'type': self._classify_vulnerability_type(description),
                        'description': description.strip(),
                        'source': 'llm_alt'
                    }
                    vulnerabilities.append(vuln)
                elif len(match) == 2:  # Line, description
                    line_num, description = match
                    vuln = {
                        'line': int(line_num) + line_offset,
                        'severity': 'MEDIUM',  # Default severity
                        'type': self._classify_vulnerability_type(description),
                        'description': description.strip(),
                        'source': 'llm_alt'
                    }
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity string to standard format"""
        severity_clean = severity.lower().strip()
        return self.severity_mapping.get(severity_clean, 'MEDIUM')

    def _classify_vulnerability_type(self, description: str) -> str:
        """Classify vulnerability type based on description"""
        description_lower = description.lower()

        for vuln_type, patterns in self.vuln_type_patterns.items():
            for pattern in patterns:
                if re.search(pattern, description_lower):
                    return vuln_type

        return 'Security Issue'  # Generic fallback

    def extract_vulnerabilities(self, code_content: str) -> List[Dict[str, Any]]:
        """
        Extract vulnerabilities using pattern matching on raw code

        Args:
            code_content (str): Raw C/C++ source code

        Returns:
            List[Dict]: Additional vulnerabilities found
        """
        vulnerabilities = []
        lines = code_content.split('\n')

        # Advanced pattern-based detection
        vulnerabilities.extend(self._detect_cryptographic_issues(lines))
        vulnerabilities.extend(self._detect_input_validation_issues(lines))
        vulnerabilities.extend(self._detect_resource_management_issues(lines))
        vulnerabilities.extend(self._detect_concurrency_issues(lines))

        return vulnerabilities

    def _detect_cryptographic_issues(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect cryptographic and security-related issues"""
        vulnerabilities = []

        crypto_patterns = {
            'Weak Random': [r'rand\(\)', r'random\(\)'],
            'Hardcoded Secret': [r'password\s*=\s*["\']', r'key\s*=\s*["\']', r'token\s*=\s*["\']'],
            'Weak Hash': [r'md5\(', r'sha1\('],
            'Insecure Protocol': [r'http://', r'ftp://', r'telnet'],
        }

        for i, line in enumerate(lines, 1):
            line_clean = line.strip().lower()

            for vuln_type, patterns in crypto_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line_clean):
                        vulnerabilities.append({
                            'line': i,
                            'severity': 'MEDIUM',
                            'type': vuln_type,
                            'description': f'Potential {vuln_type.lower()} detected',
                            'context': line.strip(),
                            'source': 'pattern'
                        })

        return vulnerabilities

    def _detect_input_validation_issues(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect input validation problems"""
        vulnerabilities = []

        validation_patterns = {
            'Missing Input Validation': [
                r'scanf\s*\([^,]*,\s*[^)]+\)',  # scanf without validation
                r'atoi\s*\(',  # atoi without validation
                r'strtol\s*\('  # strtol without validation
            ],
            'SQL Injection Risk': [
                r'sql.*\+.*user', r'query.*\+.*input', r'execute.*\+.*param'
            ],
            'Path Traversal': [
                r'fopen\s*\([^,)]*\.\.[^)]*\)',  # fopen with ..
                r'open\s*\([^,)]*\.\.[^)]*\)',  # open with ..
                r'access\s*\([^,)]*\.\.[^)]*\)',  # access with ..
            ]
        }

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            for vuln_type, patterns in validation_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line_clean, re.IGNORECASE):
                        # Additional check for path traversal to avoid false positives
                        if vuln_type == 'Path Traversal':
                            # Only flag if it's actually a file operation, not just a string
                            if not any(
                                    file_op in line_clean for file_op in ['fopen', 'open', 'access', 'stat', 'chdir']):
                                continue

                        vulnerabilities.append({
                            'line': i,
                            'severity': 'HIGH' if 'injection' in vuln_type.lower() else 'MEDIUM',
                            'type': vuln_type,
                            'description': f'{vuln_type} vulnerability detected',
                            'context': line.strip(),
                            'source': 'pattern'
                        })

        return vulnerabilities

    def _detect_resource_management_issues(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect resource management problems"""
        vulnerabilities = []
        file_handles = set()
        allocated_vars = set()

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            # Track file handles
            file_open_match = re.search(r'(\w+)\s*=\s*fopen\s*\(', line_clean)
            if file_open_match:
                file_handles.add(file_open_match.group(1))

            # Check for file close
            file_close_match = re.search(r'fclose\s*\(\s*(\w+)', line_clean)
            if file_close_match:
                file_handles.discard(file_close_match.group(1))

            # Track memory allocations
            alloc_match = re.search(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(', line_clean)
            if alloc_match:
                allocated_vars.add(alloc_match.group(1))

            # Check for memory free
            free_match = re.search(r'free\s*\(\s*(\w+)', line_clean)
            if free_match:
                allocated_vars.discard(free_match.group(1))

        # Report unclosed file handles
        for handle in file_handles:
            vulnerabilities.append({
                'line': 0,  # Can't determine exact line
                'severity': 'MEDIUM',
                'type': 'Resource Leak',
                'description': f'File handle "{handle}" may not be properly closed',
                'source': 'pattern'
            })

        # Report unfreed memory
        for var in allocated_vars:
            vulnerabilities.append({
                'line': 0,  # Can't determine exact line
                'severity': 'MEDIUM',
                'type': 'Memory Leak',
                'description': f'Allocated memory "{var}" may not be freed',
                'source': 'pattern'
            })

        return vulnerabilities

    def _detect_concurrency_issues(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Detect concurrency and threading issues"""
        vulnerabilities = []

        # Look for threading without proper synchronization
        has_threads = False
        has_synchronization = False
        thread_line = 0

        for i, line in enumerate(lines, 1):
            line_clean = line.strip().lower()

            # Check for threading
            if any(thread_pattern in line_clean for thread_pattern in [
                'pthread_create', 'std::thread', 'createthread'
            ]):
                has_threads = True
                if thread_line == 0:
                    thread_line = i

            # Check for synchronization primitives
            if any(sync_pattern in line_clean for sync_pattern in [
                'mutex', 'lock', 'semaphore', 'critical_section', 'atomic'
            ]):
                has_synchronization = True

            # Check for global variable access in threaded context
            if has_threads and re.search(r'(global|static)\s+\w+', line, re.IGNORECASE):
                vulnerabilities.append({
                    'line': i,
                    'severity': 'MEDIUM',
                    'type': 'Race Condition',
                    'description': 'Global/static variable access in multi-threaded context',
                    'context': line.strip(),
                    'source': 'pattern'
                })

        # If we have threads but no synchronization
        if has_threads and not has_synchronization:
            vulnerabilities.append({
                'line': thread_line,
                'severity': 'HIGH',
                'type': 'Race Condition',
                'description': 'Multi-threading detected without synchronization primitives',
                'source': 'pattern'
            })

        # Check for specific race condition patterns
        race_patterns = [
            (r'sleep\s*\(\s*\d+\s*\)', 'Sleep-based synchronization (unreliable)'),
            (r'volatile\s+(?!sig_atomic_t)', 'Volatile without proper synchronization'),
            (r'signal\s*\(', 'Signal handler without async-signal-safe functions')
        ]

        for i, line in enumerate(lines, 1):
            for pattern, description in race_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'line': i,
                        'severity': 'MEDIUM',
                        'type': 'Race Condition',
                        'description': description,
                        'context': line.strip(),
                        'source': 'pattern'
                    })

        return vulnerabilities