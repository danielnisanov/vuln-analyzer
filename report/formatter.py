"""
Report Formatter for Vulnerability Analysis Results
Formats vulnerability reports in various output formats
"""
import json
from datetime import datetime
from typing import Dict, Any, List


class ReportFormatter:
    """
    Formats vulnerability analysis results into various output formats
    """

    def __init__(self):
        """Initialize the report formatter"""
        self.severity_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',  # Yellow
            'MEDIUM': '\033[94m',  # Blue
            'LOW': '\033[92m',  # Green
            'RESET': '\033[0m'  # Reset
        }

    def format_report(self, results: Dict[str, Any], format_type: str = 'text',
                      include_fixes: bool = False, use_colors: bool = True) -> str:
        """
        Format the vulnerability report

        Args:
            results (Dict): Analysis results
            format_type (str): Output format ('text', 'json', 'html')
            include_fixes (bool): Include suggested fixes
            use_colors (bool): Use ANSI colors in text output

        Returns:
            str: Formatted report
        """
        if format_type == 'json':
            return self._format_json(results)
        elif format_type == 'html':
            return self._format_html(results, include_fixes)
        else:  # text
            return self._format_text(results, include_fixes, use_colors)

    def _format_text(self, results: Dict[str, Any], include_fixes: bool, use_colors: bool) -> str:
        """Format report as plain text"""
        lines = []

        # Header
        lines.append("=" * 70)
        lines.append(f"# C/C++ Vulnerability Analysis Report")
        lines.append(f"# File: {results.get('filename', 'Unknown')}")
        lines.append(f"# Analysis Time: {results.get('analysis_time', 0):.2f} seconds")
        lines.append(f"# Chunks Analyzed: {results.get('chunks_analyzed', 0)}")
        lines.append("=" * 70)
        lines.append("")

        # Summary Statistics
        stats = results.get('statistics', {})
        if stats:
            lines.append("## Summary")
            lines.append("-" * 40)
            lines.append(f"Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
            lines.append(f"Critical: {stats.get('critical_count', 0)}")
            lines.append(f"High:     {stats.get('high_count', 0)}")
            lines.append(f"Medium:   {stats.get('medium_count', 0)}")
            lines.append(f"Low:      {stats.get('low_count', 0)}")
            lines.append(f"Risk Score: {stats.get('risk_score', 0)}")

            if stats.get('most_common_type'):
                lines.append(f"Most Common Type: {stats['most_common_type']}")

            lines.append("")

        # Vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            lines.append("## Vulnerabilities Found")
            lines.append("-" * 40)

            for vuln in vulnerabilities:
                line_num = vuln.get('line', 0)
                severity = vuln.get('severity', 'UNKNOWN')
                vuln_type = vuln.get('type', 'Unknown')
                description = vuln.get('description', 'No description')

                # Format vulnerability line
                if use_colors and severity in self.severity_colors:
                    color = self.severity_colors[severity]
                    reset = self.severity_colors['RESET']
                    vuln_line = f"Line {line_num}: {color}[{severity}]{reset} {vuln_type} - {description}"
                else:
                    vuln_line = f"Line {line_num}: [{severity}] {vuln_type} - {description}"

                lines.append(vuln_line)

                # Add context if available
                if vuln.get('context'):
                    lines.append(f"  Context: {vuln['context'][:100]}...")

                # Add CWE if available
                if vuln.get('cwe'):
                    lines.append(f"  CWE: {vuln['cwe']}")

                # Add suggested fix if requested
                if include_fixes and vuln.get('suggested_fix'):
                    lines.append(f"  Fix: {vuln['suggested_fix']}")

                lines.append("")  # Empty line between vulnerabilities
        else:
            lines.append("No vulnerabilities detected.")
            lines.append("")

        # Footer
        lines.append("-" * 70)
        lines.append(f"Report generated at: {datetime.now().isoformat()}")

        return "\n".join(lines)

    def _format_json(self, results: Dict[str, Any]) -> str:
        """Format report as JSON"""
        # Add metadata
        output = {
            'metadata': {
                'filename': results.get('filename', 'Unknown'),
                'analysis_time': results.get('analysis_time', 0),
                'chunks_analyzed': results.get('chunks_analyzed', 0),
                'timestamp': datetime.now().isoformat()
            },
            'statistics': results.get('statistics', {}),
            'vulnerabilities': results.get('vulnerabilities', [])
        }

        return json.dumps(output, indent=2)

