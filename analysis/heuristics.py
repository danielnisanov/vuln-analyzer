"""
Heuristic Analyzer for C/C++ Vulnerability Detection
Provides additional rule-based vulnerability detection
"""
import re
from typing import List, Dict, Any
from dataclasses import dataclass


class HeuristicAnalyzer:
    """
    Performs heuristic-based vulnerability analysis on code chunks
    """

    def __init__(self):
        """Initialize the heuristic analyzer with patterns and rules"""

        # Dangerous function patterns
        self.dangerous_functions = {
            'gets': {'severity': 'CRITICAL', 'type': 'Buffer Overflow',
                    'reason': 'No bounds checking, deprecated function'},
            'strcpy': {'severity': 'HIGH', 'type': 'Buffer Overflow',
                      'reason': 'No bounds checking on destination buffer'},
            'strcat': {'severity': 'HIGH', 'type': 'Buffer Overflow',
                      'reason': 'No bounds checking on concatenation'},
            'sprintf': {'severity': 'HIGH', 'type': 'Buffer Overflow',
                       'reason': 'No bounds checking on output buffer'},
            'scanf': {'severity': 'MEDIUM', 'type': 'Buffer Overflow',
                     'reason': 'Potential buffer overflow with %s'},
            'system': {'severity': 'HIGH', 'type': 'Command Injection',
                      'reason': 'Potential command injection vulnerability'},
            'exec': {'severity': 'HIGH', 'type': 'Command Injection',
                    'reason': 'Potential command execution vulnerability'},
            'popen': {'severity': 'HIGH', 'type': 'Command Injection',
                     'reason': 'Potential command injection via pipe'},
        }

        # Compile regex patterns
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for efficient matching"""

        # Pattern for function calls
        self.func_call_pattern = re.compile(
            r'\b(\w+)\s*\([^)]*\)',
            re.MULTILINE
        )

        # Pattern for memory allocation
        self.malloc_pattern = re.compile(
            r'\b(malloc|calloc|realloc)\s*\([^)]+\)',
            re.MULTILINE
        )

        # Pattern for memory deallocation
        self.free_pattern = re.compile(
            r'\bfree\s*\([^)]+\)',
            re.MULTILINE
        )

        # Pattern for pointer arithmetic
        self.pointer_arithmetic_pattern = re.compile(
            r'(\*\w+|\w+\[\w+\])\s*[+\-*/]=',
            re.MULTILINE
        )

        # Pattern for unchecked input
        self.unchecked_input_pattern = re.compile(
            r'(scanf|fscanf|sscanf|gets|fgets)\s*\([^)]*\)',
            re.MULTILINE
        )

        # Pattern for format strings
        self.format_string_pattern = re.compile(
            r'(printf|fprintf|sprintf|snprintf)\s*\([^,)]*[^"]\s*\)',
            re.MULTILINE
        )

    def analyze_chunk(self, chunk) -> List[Dict[str, Any]]:
        """
        Analyze a code chunk using heuristic rules

        Args:
            chunk: CodeChunk object containing code to analyze

        Returns:
            List[Dict]: List of detected vulnerabilities
        """
        vulnerabilities = []
        lines = chunk.content.split('\n')

        # Analyze each line
        for relative_line, line in enumerate(lines, 1):
            actual_line = chunk.start_line + relative_line - 1

            # Check for dangerous functions
            vulns = self._check_dangerous_functions(line, actual_line)
            vulnerabilities.extend(vulns)

            # Check for format string vulnerabilities
            vuln = self._check_format_strings(line, actual_line)
            if vuln:
                vulnerabilities.append(vuln)

            # Check for integer overflows
            vuln = self._check_integer_overflow(line, actual_line)
            if vuln:
                vulnerabilities.append(vuln)

        # Analyze chunk as a whole
        vulnerabilities.extend(self._analyze_memory_management(chunk))
        vulnerabilities.extend(self._analyze_error_handling(chunk))
        vulnerabilities.extend(self._analyze_authentication(chunk))

        return vulnerabilities

    def _check_dangerous_functions(self, line: str, line_num: int) -> List[Dict[str, Any]]:
        """Check for use of dangerous functions"""
        vulnerabilities = []

        for func_name, details in self.dangerous_functions.items():
            # Create pattern for this specific function
            pattern = rf'\b{func_name}\s*\('

            if re.search(pattern, line):
                vulnerabilities.append({
                    'line': line_num,
                    'severity': details['severity'],
                    'type': details['type'],
                    'description': f"Use of dangerous function {func_name}(): {details['reason']}",
                    'context': line.strip(),
                    'source': 'heuristic'
                })

        return vulnerabilities

    def _check_format_strings(self, line: str, line_num: int) -> Dict[str, Any]:
        """Check for format string vulnerabilities"""

        # Check for printf family functions with non-literal format strings
        printf_pattern = r'(printf|fprintf|sprintf|snprintf)\s*\(\s*([^,")]+)\s*\)'
        match = re.search(printf_pattern, line)

        if match:
            func_name = match.group(1)
            first_arg = match.group(2)

            # Check if first argument is not a string literal
            if not (first_arg.startswith('"') or 'stderr' in first_arg or 'stdout' in first_arg):
                return {
                    'line': line_num,
                    'severity': 'HIGH',
                    'type': 'Format String Vulnerability',
                    'description': f'{func_name}() with potentially user-controlled format string',
                    'context': line.strip(),
                    'source': 'heuristic'
                }

        return None

    def _check_integer_overflow(self, line: str, line_num: int) -> Dict[str, Any]:
        """Check for potential integer overflow vulnerabilities"""

        # Check for arithmetic operations on integers without bounds checking
        patterns = [
            r'(\w+)\s*\*=?\s*(\w+)',  # Multiplication
            r'(\w+)\s*\+=?\s*(\w+)',  # Addition
            r'(\w+)\s*<<=?\s*(\w+)',  # Left shift
        ]

        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                # Check if it involves size calculations or array indexing
                if any(keyword in line.lower() for keyword in ['size', 'len', 'count', 'num', 'malloc', 'alloc']):
                    return {
                        'line': line_num,
                        'severity': 'MEDIUM',
                        'type': 'Integer Overflow',
                        'description': 'Potential integer overflow in size calculation',
                        'context': line.strip(),
                        'source': 'heuristic'
                    }

        return None

    def _analyze_memory_management(self, chunk) -> List[Dict[str, Any]]:
        """Analyze memory management issues in the chunk"""
        vulnerabilities = []

        # Find all malloc/calloc/realloc calls
        allocations = {}
        for match in self.malloc_pattern.finditer(chunk.content):
            # Try to extract variable name
            line_start = chunk.content.rfind('\n', 0, match.start()) + 1
            line_end = chunk.content.find('\n', match.end())
            if line_end == -1:
                line_end = len(chunk.content)

            line = chunk.content[line_start:line_end]
            var_match = re.search(r'(\w+)\s*=\s*' + re.escape(match.group()), line)
            if var_match:
                var_name = var_match.group(1)
                line_num = chunk.content[:match.start()].count('\n') + chunk.start_line
                allocations[var_name] = line_num

        # Find all free calls
        freed_vars = set()
        for match in self.free_pattern.finditer(chunk.content):
            var_match = re.search(r'free\s*\(\s*(\w+)', match.group())
            if var_match:
                freed_vars.add(var_match.group(1))

        # Check for memory leaks
        for var_name, line_num in allocations.items():
            if var_name not in freed_vars:
                vulnerabilities.append({
                    'line': line_num,
                    'severity': 'MEDIUM',
                    'type': 'Memory Leak',
                    'description': f'Allocated memory ({var_name}) may not be freed',
                    'source': 'heuristic'
                })

        # Check for double free
        free_calls = {}
        for match in self.free_pattern.finditer(chunk.content):
            var_match = re.search(r'free\s*\(\s*(\w+)', match.group())
            if var_match:
                var_name = var_match.group(1)
                line_num = chunk.content[:match.start()].count('\n') + chunk.start_line

                if var_name in free_calls:
                    vulnerabilities.append({
                        'line': line_num,
                        'severity': 'HIGH',
                        'type': 'Double Free',
                        'description': f'Variable {var_name} may be freed multiple times',
                        'source': 'heuristic'
                    })
                else:
                    free_calls[var_name] = line_num

        return vulnerabilities

    def _analyze_error_handling(self, chunk) -> List[Dict[str, Any]]:
        """Analyze error handling issues"""
        vulnerabilities = []

        # Check for unchecked return values
        unchecked_functions = [
            'fopen', 'malloc', 'calloc', 'realloc',
            'socket', 'bind', 'listen', 'accept',
            'pthread_create', 'pthread_mutex_lock'
        ]

        for func in unchecked_functions:
            pattern = rf'{func}\s*\([^)]*\)'
            matches = re.finditer(pattern, chunk.content)

            for match in matches:
                # Check if return value is checked
                line_start = chunk.content.rfind('\n', 0, match.start()) + 1
                line_end = chunk.content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(chunk.content)

                # Look for error checking in the next few lines
                check_area = chunk.content[line_start:min(line_end + 200, len(chunk.content))]

                # Simple heuristic: look for if statements or null checks
                if not any(pattern in check_area for pattern in ['if', 'NULL', '== -1', '!= 0', '< 0']):
                    line_num = chunk.content[:match.start()].count('\n') + chunk.start_line
                    vulnerabilities.append({
                        'line': line_num,
                        'severity': 'MEDIUM',
                        'type': 'Missing Error Check',
                        'description': f'Return value of {func}() not checked',
                        'source': 'heuristic'
                    })

        return vulnerabilities

    def _analyze_authentication(self, chunk) -> List[Dict[str, Any]]:
        """Analyze authentication and cryptographic issues"""
        vulnerabilities = []

        # Check for hardcoded passwords or keys
        hardcoded_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded Password'),
            (r'passwd\s*=\s*["\'][^"\']+["\']', 'Hardcoded Password'),
            (r'key\s*=\s*["\'][^"\']+["\']', 'Hardcoded Encryption Key'),
            (r'token\s*=\s*["\'][^"\']+["\']', 'Hardcoded Token'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded Secret'),
        ]

        for pattern, vuln_type in hardcoded_patterns:
            matches = re.finditer(pattern, chunk.content, re.IGNORECASE)
            for match in matches:
                line_num = chunk.content[:match.start()].count('\n') + chunk.start_line
                vulnerabilities.append({
                    'line': line_num,
                    'severity': 'HIGH',
                    'type': vuln_type,
                    'description': f'{vuln_type} detected in source code',
                    'context': match.group()[:50] + '...' if len(match.group()) > 50 else match.group(),
                    'source': 'heuristic'
                })

        # Check for weak random number generation
        weak_random_patterns = [
            (r'\brand\s*\(\s*\)', 'rand()'),
            (r'\brandom\s*\(\s*\)', 'random()'),
        ]

        for pattern, func_name in weak_random_patterns:
            if re.search(pattern, chunk.content):
                # Find line number of first occurrence
                match = re.search(pattern, chunk.content)
                line_num = chunk.content[:match.start()].count('\n') + chunk.start_line
                vulnerabilities.append({
                    'line': line_num,
                    'severity': 'MEDIUM',
                    'type': 'Weak Random Number Generator',
                    'description': f'Use of weak random function {func_name} for security-sensitive operations',
                    'source': 'heuristic'
                })

        return vulnerabilities