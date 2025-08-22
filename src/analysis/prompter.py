"""
Prompt Engineering Module for Vulnerability Analysis
Handles all prompt templates and generation for LLM interactions
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class PromptTemplate:
    """Represents a prompt template with metadata"""
    name: str
    template: str
    max_tokens: int = 800
    temperature: float = 0.1  # Low temperature for consistent analysis


class VulnerabilityPrompter:
    """
    Manages prompt templates and generation for vulnerability analysis
    """

    def __init__(self):
        """Initialize with predefined prompt templates"""
        self.templates = self._initialize_templates()
        self.current_template = "comprehensive"  # Default template

    def _initialize_templates(self) -> Dict[str, PromptTemplate]:
        """Initialize all prompt templates"""
        templates = {}

        # Comprehensive analysis template
        templates["comprehensive"] = PromptTemplate(
            name="comprehensive",
            template="""You are a security expert analyzing C/C++ code for vulnerabilities.

Analyze the following C/C++ code{filename_part} and identify potential security vulnerabilities.

Focus on these common vulnerability types:
1. Buffer overflows (stack and heap)
2. Use-after-free vulnerabilities
3. Memory leaks
4. Format string vulnerabilities
5. Integer overflows/underflows
6. Null pointer dereferences
7. Race conditions
8. Input validation issues
9. Command injection
10. Cryptographic weaknesses

For each vulnerability found, provide:
- Line number (if identifiable)
- Vulnerability type
- Brief explanation
- Severity level (Critical/High/Medium/Low)

Code to analyze:
```c
{code}
```

Output format:
Line X: [SEVERITY] Vulnerability_Type - Brief explanation

If no vulnerabilities are found, respond with: "No obvious vulnerabilities detected."

Analysis:""",
            max_tokens=800
        )

        # Quick scan template (faster, less detailed)
        templates["quick_scan"] = PromptTemplate(
            name="quick_scan",
            template="""Security quick scan for C/C++ code{filename_part}.

Check for critical vulnerabilities only:
- Buffer overflows (gets, strcpy, sprintf)
- Use-after-free
- Command injection
- Format string bugs

Code:
```c
{code}
```

Report format: Line X: [SEVERITY] Type - Description
Or: "No critical vulnerabilities detected."

Scan results:""",
            max_tokens=400
        )

        # Memory-focused template
        templates["memory_focus"] = PromptTemplate(
            name="memory_focus",
            template="""Analyze C/C++ code for memory-related vulnerabilities{filename_part}.

Focus exclusively on:
1. Memory leaks (malloc without free)
2. Use-after-free vulnerabilities
3. Double free issues
4. Buffer overflows/underflows
5. Heap corruption
6. Stack corruption
7. Uninitialized memory usage

Code to analyze:
```c
{code}
```

For each issue: Line X: [SEVERITY] Memory_Issue - Explanation

Memory analysis:""",
            max_tokens=600
        )

        # Input validation template
        templates["input_validation"] = PromptTemplate(
            name="input_validation",
            template="""Analyze C/C++ code for input validation vulnerabilities{filename_part}.

Check for:
1. Missing bounds checking
2. Integer overflows in size calculations
3. Format string vulnerabilities
4. Command injection via user input
5. Path traversal vulnerabilities
6. SQL injection risks
7. Unsafe input functions (gets, scanf %s)

Code:
```c
{code}
```

Report: Line X: [SEVERITY] Input_Issue - Description

Input validation analysis:""",
            max_tokens=600
        )

        # Concurrency template
        templates["concurrency"] = PromptTemplate(
            name="concurrency",
            template="""Analyze C/C++ code for concurrency and threading issues{filename_part}.

Focus on:
1. Race conditions
2. Deadlocks
3. Missing synchronization
4. Thread safety violations
5. Atomic operation issues
6. Signal handler vulnerabilities

Code:
```c
{code}
```

Format: Line X: [SEVERITY] Concurrency_Issue - Explanation

Concurrency analysis:""",
            max_tokens=500
        )

        # CWE-focused template
        templates["cwe_mapping"] = PromptTemplate(
            name="cwe_mapping",
            template="""Analyze C/C++ code and map vulnerabilities to CWE IDs{filename_part}.

Identify vulnerabilities and provide:
- Line number
- CWE ID (e.g., CWE-120 for buffer overflow)
- Vulnerability name
- Severity (Critical/High/Medium/Low)
- Brief description

Common CWEs to check:
- CWE-120: Buffer overflow
- CWE-416: Use after free
- CWE-401: Memory leak
- CWE-134: Format string
- CWE-190: Integer overflow
- CWE-476: NULL pointer dereference
- CWE-78: Command injection

Code:
```c
{code}
```

Format: Line X: [SEVERITY] CWE-XXX: Name - Description

CWE analysis:""",
            max_tokens=700
        )

        # Fix suggestion template
        templates["with_fixes"] = PromptTemplate(
            name="with_fixes",
            template="""Analyze C/C++ code for vulnerabilities and suggest fixes{filename_part}.

For each vulnerability:
1. Identify the issue (line, type, severity)
2. Explain why it's vulnerable
3. Provide a specific fix

Code to analyze:
```c
{code}
```

Format:
Line X: [SEVERITY] Type - Description
Fix: Specific remediation suggestion

Analysis with fixes:""",
            max_tokens=1000
        )

        # OWASP Top 10 template
        templates["owasp_check"] = PromptTemplate(
            name="owasp_check",
            template="""Check C/C++ code against OWASP vulnerability categories{filename_part}.

Focus on:
- Injection vulnerabilities
- Broken authentication
- Sensitive data exposure
- External entity attacks
- Broken access control
- Security misconfiguration
- Insecure deserialization

Code:
```c
{code}
```

Report: Line X: [SEVERITY] OWASP_Category - Details

OWASP analysis:""",
            max_tokens=600
        )

        return templates

    def create_prompt(self, code: str, filename: str = "", template_name: Optional[str] = None) -> str:
        """
        Create a prompt for vulnerability analysis

        Args:
            code (str): The C/C++ source code to analyze
            filename (str): Optional filename for context
            template_name (str): Template to use (default: current_template)

        Returns:
            str: Formatted prompt ready for LLM
        """
        template_name = template_name or self.current_template

        if template_name not in self.templates:
            raise ValueError(f"Unknown template: {template_name}")

        template = self.templates[template_name]

        # Prepare filename part
        filename_part = f" from file '{filename}'" if filename else ""

        # Format the prompt
        prompt = template.template.format(
            code=code,
            filename_part=filename_part
        )

        return prompt

    def create_contextual_prompt(self, code: str, context: Dict[str, Any]) -> str:
        """
        Create a context-aware prompt based on code characteristics

        Args:
            code (str): The C/C++ source code
            context (dict): Context information about the code

        Returns:
            str: Contextual prompt
        """
        # Analyze code characteristics
        code_lower = code.lower()

        # Determine best template based on code
        if any(term in code_lower for term in ['pthread', 'thread', 'mutex', 'lock']):
            template_name = "concurrency"
        elif any(term in code_lower for term in ['malloc', 'free', 'calloc', 'realloc']):
            template_name = "memory_focus"
        elif any(term in code_lower for term in ['gets', 'scanf', 'input', 'argv']):
            template_name = "input_validation"
        else:
            template_name = "comprehensive"

        filename = context.get('filename', '')
        return self.create_prompt(code, filename, template_name)

    def create_chunk_prompt(self, chunk_content: str, chunk_info: Dict[str, Any]) -> str:
        """
        Create a prompt specifically for code chunks

        Args:
            chunk_content (str): The code chunk
            chunk_info (dict): Information about the chunk

        Returns:
            str: Chunk-specific prompt
        """
        chunk_type = chunk_info.get('chunk_type', 'unknown')
        start_line = chunk_info.get('start_line', 1)
        function_name = chunk_info.get('function_name', '')

        # Add chunk context to prompt
        context_prefix = f"""Analyzing {chunk_type} chunk starting at line {start_line}"""

        if function_name:
            context_prefix += f" (function: {function_name})"

        context_prefix += ":\n\n"

        # Choose appropriate template based on chunk type
        if chunk_type == 'function':
            template_name = "comprehensive"
        elif chunk_type == 'includes':
            template_name = "quick_scan"
        else:
            template_name = self.current_template

        base_prompt = self.create_prompt(chunk_content, "", template_name)
        return context_prefix + base_prompt

    def create_refinement_prompt(self, code: str, initial_results: List[Dict[str, Any]]) -> str:
        """
        Create a prompt to refine initial analysis results

        Args:
            code (str): The original code
            initial_results (list): Initial vulnerability findings

        Returns:
            str: Refinement prompt
        """
        prompt = """Review and refine the following vulnerability analysis.

Initial findings:
"""
        for vuln in initial_results[:10]:  # Limit to first 10 for context
            prompt += f"- Line {vuln.get('line')}: {vuln.get('type')} - {vuln.get('description')}\n"

        prompt += f"""

Original code:
```c
{code[:1000]}  # First 1000 chars
```

Please:
1. Verify these findings are accurate
2. Check for false positives
3. Add any missed critical vulnerabilities
4. Adjust severity levels if needed

Refined analysis:"""

        return prompt

    def create_comparison_prompt(self, code1: str, code2: str) -> str:
        """
        Create a prompt to compare two code versions for security improvements

        Args:
            code1 (str): Original code
            code2 (str): Modified code

        Returns:
            str: Comparison prompt
        """
        prompt = f"""Compare two versions of C/C++ code for security improvements or regressions.

Original code:
```c
{code1[:500]}
```

Modified code:
```c
{code2[:500]}
```

Identify:
1. Fixed vulnerabilities
2. New vulnerabilities introduced
3. Remaining vulnerabilities
4. Security improvements

Comparison analysis:"""

        return prompt

    def set_template(self, template_name: str):
        """Set the current active template"""
        if template_name not in self.templates:
            raise ValueError(f"Unknown template: {template_name}")
        self.current_template = template_name

    def get_template_names(self) -> List[str]:
        """Get list of available template names"""
        return list(self.templates.keys())

    def get_template_info(self, template_name: str) -> Dict[str, Any]:
        """Get information about a specific template"""
        if template_name not in self.templates:
            return {}

        template = self.templates[template_name]
        return {
            'name': template.name,
            'max_tokens': template.max_tokens,
            'temperature': template.temperature,
            'description': template.template[:100] + '...'
        }

    def customize_template(self, name: str, template_str: str, max_tokens: int = 800):
        """Add or update a custom template"""
        self.templates[name] = PromptTemplate(
            name=name,
            template=template_str,
            max_tokens=max_tokens
        )


# Example usage and testing
if __name__ == "__main__":
    prompter = VulnerabilityPrompter()

    # Test code sample
    test_code = """
    #include <stdio.h>
    #include <string.h>

    void vulnerable_function() {
        char buffer[10];
        gets(buffer);  // Vulnerable
        printf(buffer);  // Format string vulnerability
    }
    """

    # Test different templates
    print("Available templates:", prompter.get_template_names())
    print("\n" + "=" * 50 + "\n")

    # Test comprehensive prompt
    prompt = prompter.create_prompt(test_code, "test.c", "comprehensive")
    print("Comprehensive prompt (first 500 chars):")
    print(prompt[:500])
    print("\n" + "=" * 50 + "\n")

    # Test contextual prompt
    context = {'filename': 'test.c', 'has_threads': False}
    contextual = prompter.create_contextual_prompt(test_code, context)
    print("Contextual prompt (first 500 chars):")
    print(contextual[:500])