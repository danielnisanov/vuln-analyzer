#!/usr/bin/env python3
"""
Vulnerability Analyzer CLI Tool
Main entry point for the C/C++ vulnerability detection system
"""

import argparse
import os
import sys
import json
import time
from pathlib import Path

# Import from src package structure
from src.analysis import (
    ONNXLLMBackend,
    CodeChunker,
    VulnerabilityExtractor,
    HeuristicAnalyzer,
    VulnerabilityPrompter
)
from src.report import ReportFormatter


class VulnerabilityAnalyzer:
    """Main vulnerability analyzer class"""

    def __init__(self, model_path="./models/phi-4", verbose=False, template="comprehensive"):
        """
        Initialize the analyzer

        Args:
            model_path (str): Path to the LLM model
            verbose (bool): Enable verbose output
            template (str): Default analysis template
        """
        self.model_path = model_path
        self.verbose = verbose
        self.template = template

        # Initialize components
        self.llm_backend = ONNXLLMBackend(model_path)
        self.llm_backend.set_analysis_template(template)
        self.chunker = CodeChunker(max_chunk_size=3000)  # Increased chunk size
        self.extractor = VulnerabilityExtractor()
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.formatter = ReportFormatter()

        # Track analysis results
        self.results = {
            'filename': '',
            'vulnerabilities': [],
            'statistics': {},
            'analysis_time': 0,
            'chunks_analyzed': 0,
            'template_used': template
        }

    def load_model(self):
        """Load the LLM model"""
        if self.verbose:
            print("Loading LLM model...")

        success = self.llm_backend.load_model()
        if success and self.verbose:
            print("✓ Model loaded successfully")
        elif not success:
            print("⚠ Model loading failed, using rule-based analysis only")

        return success

    def analyze_file(self, file_path, output_format='text', output_file=None,
                     include_fixes=False, template=None):
        """
        Analyze a C/C++ file for vulnerabilities

        Args:
            file_path (str): Path to the C/C++ file
            output_format (str): Output format ('text', 'json', 'html')
            output_file (str): Optional output file path
            include_fixes (bool): Include suggested fixes
            template (str): Analysis template to use

        Returns:
            str: Analysis results
        """
        start_time = time.time()

        # Set template if provided
        if template:
            self.llm_backend.set_analysis_template(template)
            self.results['template_used'] = template

        # Validate file
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not file_path.lower().endswith(('.c', '.cpp', '.cc', '.cxx', '.h', '.hpp')):
            raise ValueError("File must be a C/C++ source file")

        self.results['filename'] = file_path

        if self.verbose:
            print(f"Analyzing: {file_path}")

        # Read file
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            raise Exception(f"Error reading file: {e}")

        # Chunk the code
        if self.verbose:
            print("Chunking code...")

        chunks = self.chunker.chunk_file(content)
        self.results['chunks_analyzed'] = len(chunks)

        if self.verbose:
            chunk_info = self.chunker.get_chunk_info(chunks)
            print(f"Created {len(chunks)} chunks: {chunk_info['chunk_types']}")

        # Analyze each chunk
        all_vulnerabilities = []

        for i, chunk in enumerate(chunks):
            if self.verbose and i % 10 == 0:  # Only print every 10th chunk to reduce noise
                print(f"Analyzing chunk {i + 1}/{len(chunks)} ({chunk.chunk_type})")

            # LLM Analysis
            llm_vulns = self._analyze_chunk_with_llm(chunk, file_path)

            # Heuristic Analysis
            heuristic_vulns = self.heuristic_analyzer.analyze_chunk(chunk)

            # Combine and deduplicate
            combined_vulns = self._combine_vulnerabilities(llm_vulns, heuristic_vulns)
            all_vulnerabilities.extend(combined_vulns)

        # Post-process vulnerabilities
        self.results['vulnerabilities'] = self._post_process_vulnerabilities(all_vulnerabilities)

        # Extract additional patterns
        extracted_vulns = self.extractor.extract_vulnerabilities(content)
        self.results['vulnerabilities'].extend(extracted_vulns)

        # Remove duplicates and sort
        self.results['vulnerabilities'] = self._deduplicate_and_sort(self.results['vulnerabilities'])

        # Add fixes if requested
        if include_fixes:
            self._add_suggested_fixes()

        # Calculate statistics
        self.results['statistics'] = self._calculate_statistics()
        self.results['analysis_time'] = time.time() - start_time

        # Format output
        output = self.formatter.format_report(
            self.results,
            format_type=output_format,
            include_fixes=include_fixes
        )

        # Save to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            if self.verbose:
                print(f"Report saved to: {output_file}")

        return output

    def _analyze_chunk_with_llm(self, chunk, filename):
        """Analyze a chunk using the LLM with context-aware prompting"""
        try:
            # Create chunk info for context-aware prompting
            chunk_info = {
                'chunk_type': chunk.chunk_type,
                'start_line': chunk.start_line,
                'function_name': chunk.function_name if hasattr(chunk, 'function_name') else ''
            }

            # Use the new analyze_chunk method with context
            result = self.llm_backend.analyze_chunk(chunk.content, chunk_info)

            if result:
                return self.extractor.parse_llm_output(result, chunk.start_line)
            return []
        except Exception as e:
            if self.verbose:
                print(f"LLM analysis failed for chunk: {e}")
            return []

    def _combine_vulnerabilities(self, llm_vulns, heuristic_vulns):
        """Combine LLM and heuristic analysis results"""
        return llm_vulns + heuristic_vulns

    def _post_process_vulnerabilities(self, vulnerabilities):
        """Post-process vulnerability list"""
        filtered = []

        for vuln in vulnerabilities:
            # Skip obvious false positives
            if self._is_likely_false_positive(vuln):
                continue

            # Enhance vulnerability description
            enhanced_vuln = self._enhance_vulnerability(vuln)
            filtered.append(enhanced_vuln)

        return filtered

    def _is_likely_false_positive(self, vuln):
        """Check if vulnerability is likely a false positive"""
        description = vuln.get('description', '').lower()

        # Skip generic null pointer warnings without context
        if 'null pointer' in description and not vuln.get('context'):
            return True

        # Skip very generic integer overflow warnings in safe contexts
        if 'integer overflow' in description and vuln.get('severity') == 'LOW':
            line_content = vuln.get('context', '').lower()
            if any(safe_pattern in line_content for safe_pattern in [
                'for (', 'while (', 'if (', 'printf(', 'sizeof('
            ]):
                return True

        return False

    def _enhance_vulnerability(self, vuln):
        """Enhance vulnerability with additional context"""
        vuln_type = vuln.get('type', '').lower()

        cwe_mappings = {
            'buffer overflow': 'CWE-120',
            'use after free': 'CWE-416',
            'memory leak': 'CWE-401',
            'format string': 'CWE-134',
            'integer overflow': 'CWE-190',
            'command injection': 'CWE-78',
            'null pointer': 'CWE-476',
            'race condition': 'CWE-362',
            'double free': 'CWE-415',
            'path traversal': 'CWE-22'
        }

        for pattern, cwe in cwe_mappings.items():
            if pattern in vuln_type:
                vuln['cwe'] = cwe
                break

        return vuln

    def _deduplicate_and_sort(self, vulnerabilities):
        """Remove duplicates and sort by line number and severity"""
        seen = set()
        unique_vulns = []

        for vuln in vulnerabilities:
            key = (vuln.get('line'), vuln.get('type'))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        # Sort by line number, then by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

        unique_vulns.sort(key=lambda v: (
            v.get('line', 0),
            severity_order.get(v.get('severity', 'LOW'), 4)
        ))

        return unique_vulns

    def _add_suggested_fixes(self):
        """Add suggested fixes to vulnerabilities"""
        for vuln in self.results['vulnerabilities']:
            vuln['suggested_fix'] = self._generate_fix_suggestion(vuln)

    def _generate_fix_suggestion(self, vuln):
        """Generate fix suggestion for a vulnerability"""
        vuln_type = vuln.get('type', '').lower()

        fix_suggestions = {
            'buffer overflow': {
                'gets()': 'Replace gets() with fgets() and specify buffer size',
                'strcpy()': 'Replace strcpy() with strncpy() or use safer alternatives like strlcpy()',
                'strcat()': 'Replace strcat() with strncat() and check buffer bounds',
                'sprintf()': 'Replace sprintf() with snprintf() to prevent buffer overflow'
            },
            'use after free': 'Set pointer to NULL after free() and check for NULL before use',
            'memory leak': 'Ensure every malloc()/calloc() has a corresponding free()',
            'format string': 'Use printf("%s", user_input) instead of printf(user_input)',
            'command injection': 'Avoid system() calls with user input; use safer alternatives',
            'integer overflow': 'Use appropriate data types and check bounds before arithmetic operations',
            'null pointer': 'Always check pointers for NULL before dereferencing',
            'double free': 'Set pointer to NULL after free() and check before freeing',
            'race condition': 'Use proper synchronization primitives (mutexes, locks)',
            'path traversal': 'Validate and sanitize file paths, use realpath() to resolve'
        }

        description = vuln.get('description', '').lower()

        # Find specific fix based on vulnerability details
        for vuln_category, fixes in fix_suggestions.items():
            if vuln_category in vuln_type:
                if isinstance(fixes, dict):
                    for pattern, fix in fixes.items():
                        if pattern.replace('()', '') in description:
                            return fix
                    return f"Address {vuln_category} vulnerability"
                else:
                    return fixes

        return "Review code for security best practices"

    def _calculate_statistics(self):
        """Calculate analysis statistics"""
        stats = {
            'total_vulnerabilities': len(self.results['vulnerabilities']),
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'vulnerability_types': {},
            'most_common_type': '',
            'risk_score': 0
        }

        for vuln in self.results['vulnerabilities']:
            severity = vuln.get('severity', 'LOW')
            vuln_type = vuln.get('type', 'Unknown')

            # Count by severity
            if severity == 'CRITICAL':
                stats['critical_count'] += 1
            elif severity == 'HIGH':
                stats['high_count'] += 1
            elif severity == 'MEDIUM':
                stats['medium_count'] += 1
            else:
                stats['low_count'] += 1

            # Count by type
            stats['vulnerability_types'][vuln_type] = stats['vulnerability_types'].get(vuln_type, 0) + 1

        # Find most common type
        if stats['vulnerability_types']:
            stats['most_common_type'] = max(stats['vulnerability_types'], key=stats['vulnerability_types'].get)

        # Calculate risk score (weighted by severity)
        stats['risk_score'] = (
                stats['critical_count'] * 10 +
                stats['high_count'] * 7 +
                stats['medium_count'] * 4 +
                stats['low_count'] * 1
        )

        return stats

    def cleanup(self):
        """Cleanup resources"""
        if self.llm_backend:
            self.llm_backend.cleanup()


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='C/C++ Vulnerability Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s vulnerable_code.c
  %(prog)s --format json --output report.json source.cpp
  %(prog)s --verbose --fixes vulnerable.c
  %(prog)s --template memory_focus file.c
  %(prog)s --no-model input.c
        '''
    )

    parser.add_argument('file', help='C/C++ source file to analyze')
    parser.add_argument('--model', '-m', default='./models/phi-4',
                        help='Path to LLM model directory (default: ./models/phi-4)')
    parser.add_argument('--format', '-f', choices=['text', 'json', 'html'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--fixes', action='store_true',
                        help='Include suggested fixes in output')
    parser.add_argument('--no-model', action='store_true',
                        help='Skip LLM loading, use only rule-based analysis')
    parser.add_argument('--template', '-t',
                        choices=['comprehensive', 'quick_scan', 'memory_focus',
                                 'input_validation', 'concurrency', 'cwe_mapping',
                                 'with_fixes', 'owasp_check'],
                        default='comprehensive',
                        help='Analysis template to use (default: comprehensive)')
    parser.add_argument('--list-templates', action='store_true',
                        help='List available analysis templates')
    parser.add_argument('--config', help='Configuration file (JSON)')

    args = parser.parse_args()

    # Handle list templates request
    if args.list_templates:
        prompter = VulnerabilityPrompter()
        templates = prompter.get_template_names()
        print("Available analysis templates:")
        for template in templates:
            info = prompter.get_template_info(template)
            print(f"  - {template}: Max tokens: {info['max_tokens']}")
        sys.exit(0)

    # Load configuration if provided
    config = {}
    if args.config and os.path.exists(args.config):
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")

    # Initialize analyzer
    try:
        analyzer = VulnerabilityAnalyzer(
            model_path=args.model,
            verbose=args.verbose,
            template=args.template
        )

        # Load model unless skipped
        if not args.no_model:
            model_loaded = analyzer.load_model()
            if not model_loaded and args.verbose:
                print("Continuing with rule-based analysis...")

        # Analyze file
        if args.verbose:
            print(f"Starting analysis of: {args.file}")
            print(f"Using template: {args.template}")

        result = analyzer.analyze_file(
            file_path=args.file,
            output_format=args.format,
            output_file=args.output,
            include_fixes=args.fixes,
            template=args.template
        )

        # Print to stdout if no output file specified
        if not args.output:
            print(result)

        # Print summary statistics if verbose
        if args.verbose:
            stats = analyzer.results['statistics']
            print(f"\n=== Analysis Summary ===")
            print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
            print(f"Critical: {stats['critical_count']}, High: {stats['high_count']}, "
                  f"Medium: {stats['medium_count']}, Low: {stats['low_count']}")
            print(f"Risk Score: {stats['risk_score']}")
            print(f"Analysis time: {analyzer.results['analysis_time']:.2f}s")
            print(f"Chunks analyzed: {analyzer.results['chunks_analyzed']}")
            print(f"Template used: {analyzer.results['template_used']}")

        # Cleanup
        analyzer.cleanup()

        # Exit with error code based on findings
        if analyzer.results['statistics']['critical_count'] > 0:
            sys.exit(3)  # Critical vulnerabilities found
        elif analyzer.results['statistics']['high_count'] > 0:
            sys.exit(2)  # High severity vulnerabilities found
        elif analyzer.results['statistics']['total_vulnerabilities'] > 0:
            sys.exit(1)  # Other vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities found

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(4)  # Analysis error


if __name__ == "__main__":
    main()