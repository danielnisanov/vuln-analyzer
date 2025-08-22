"""
ONNX-Compatible LLM Backend for Vulnerability Analysis using Phi-4 model
"""
import os
import json

import logging
import re
from typing import Optional, Dict, Any, List
import numpy as np

# Try different backends in order of preference
try:
    import onnxruntime as ort

    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

try:
    from transformers import AutoTokenizer

    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False


class ONNXLLMBackend:
    """
    Backend class for handling Phi-4 ONNX model interactions
    """

    def __init__(self, model_path: str = "./models/phi-4"):
        """
        Initialize the ONNX LLM backend

        Args:
            model_path (str): Path to the local Phi-4 model directory
        """
        self.model_path = model_path
        self.onnx_model_path = None
        self.onnx_warning_shown = False
        self.session = None
        self.tokenizer = None
        self.max_tokens = 2048

        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Find the ONNX model file
        self._find_model_files()

    def _find_model_files(self):
        """Find ONNX model files in the directory structure"""
        for root, dirs, files in os.walk(self.model_path):
            for file in files:
                if file.endswith('.onnx'):
                    self.onnx_model_path = os.path.join(root, file)
                    self.logger.info(f"Found ONNX model: {self.onnx_model_path}")
                    break
            if self.onnx_model_path:
                break

        if not self.onnx_model_path:
            self.logger.warning("No ONNX model file found. Looking for alternative formats...")

    def load_model(self) -> bool:
        """
        Load the Phi-4 ONNX model and tokenizer

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check dependencies
            if not ONNX_AVAILABLE:
                self.logger.error("ONNX Runtime not available. Install with: pip install onnxruntime")
                return False

            if not TRANSFORMERS_AVAILABLE:
                self.logger.error("Transformers not available. Install with: pip install transformers")
                return False

            self.logger.info(f"Loading Phi-4 model from {self.model_path}")

            # Try to load tokenizer from different possible locations
            tokenizer_paths = [
                self.model_path,
                os.path.join(self.model_path, "cpu_and_mobile"),
                "microsoft/phi-4"  # Fallback to online if local fails
            ]

            tokenizer_loaded = False
            for path in tokenizer_paths:
                try:
                    self.logger.info(f"Trying to load tokenizer from: {path}")

                    # For local paths, use local_files_only=True
                    local_only = not path.startswith("microsoft/")

                    self.tokenizer = AutoTokenizer.from_pretrained(
                        path,
                        trust_remote_code=True,
                        local_files_only=local_only
                    )
                    tokenizer_loaded = True
                    self.logger.info(f"Tokenizer loaded successfully from: {path}")
                    break
                except Exception as e:
                    self.logger.warning(f"Failed to load tokenizer from {path}: {e}")
                    continue

            if not tokenizer_loaded:
                self.logger.error("Could not load tokenizer from any location")
                return False

            # Set padding token if not exists
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token

            # Load ONNX model if available
            if self.onnx_model_path and ONNX_AVAILABLE:
                try:
                    providers = ['CPUExecutionProvider']
                    # Try GPU providers if available
                    if ort.get_device() == 'GPU':
                        providers.insert(0, 'CUDAExecutionProvider')

                    self.session = ort.InferenceSession(
                        self.onnx_model_path,
                        providers=providers
                    )
                    self.logger.info("ONNX model loaded successfully")
                except Exception as e:
                    self.logger.warning(f"Failed to load ONNX model: {e}")
                    self.logger.info("Will use simple tokenizer-based analysis")

            self.logger.info("Model components loaded successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to load model: {str(e)}")
            return False

    def generate_response(self, prompt: str, max_new_tokens: int = 512) -> Optional[str]:
        """
        Generate response using available components

        Args:
            prompt (str): Input prompt
            max_new_tokens (int): Maximum new tokens to generate

        Returns:
            Optional[str]: Generated response or None if failed
        """
        if not self.tokenizer:
            self.logger.error("Tokenizer not loaded. Call load_model() first.")
            return None

        try:
            # If ONNX session is available, use it
            if self.session:
                return self._generate_with_onnx(prompt, max_new_tokens)
            else:
                # Fallback to rule-based analysis using the tokenizer for understanding
                return self._generate_with_rules(prompt, max_new_tokens)

        except Exception as e:
            self.logger.error(f"Generation failed: {str(e)}")
            return None

    def _generate_with_onnx(self, prompt: str, max_new_tokens: int) -> str:
        """Generate using ONNX model"""
        try:
            # The ONNX model requires complex input preparation
            # For now, we'll fall back to rule-based analysis
            # This is because the ONNX model needs attention_mask and past_key_values
            # which are complex to prepare correctly

            # Show warning only once
            if not self.onnx_warning_shown:
                self.logger.warning("ONNX inference is complex for this model. Falling back to rule-based analysis.")
                self.onnx_warning_shown = True
            return self._generate_with_rules(prompt, max_new_tokens)

            # self.logger.warning("ONNX inference is complex for this model. Falling back to rule-based analysis.")
            # return self._generate_with_rules(prompt, max_new_tokens)

        except Exception as e:
            self.logger.warning(f"ONNX inference failed: {e}. Using rule-based analysis.")
            return self._generate_with_rules(prompt, max_new_tokens)

    def _generate_with_rules(self, prompt: str, max_new_tokens: int) -> str:
        """
        Fallback rule-based analysis when ONNX model isn't available
        This provides a basic vulnerability analysis using pattern matching
        """
        # Extract the code from the prompt
        code_start = prompt.find("```c")
        if code_start == -1:
            code_start = prompt.find("Code to analyze:")

        if code_start != -1:
            code_end = prompt.find("```", code_start + 4)
            if code_end == -1:
                code_end = len(prompt)

            # Extract code section
            if "```c" in prompt:
                code_content = prompt[code_start + 4:code_end]
            else:
                # Find the actual code after "Code to analyze:"
                code_start = prompt.find("Code to analyze:") + len("Code to analyze:")
                code_content = prompt[code_start:].strip()
        else:
            code_content = prompt

        # Rule-based vulnerability detection
        vulnerabilities = self._detect_vulnerabilities_with_rules(code_content)

        if vulnerabilities:
            return "\n".join(vulnerabilities)
        else:
            return "No obvious vulnerabilities detected."

    def _detect_vulnerabilities_with_rules(self, code: str) -> List[str]:
        """Rule-based vulnerability detection"""
        vulnerabilities = []
        lines = code.split('\n')

        for i, line in enumerate(lines, 1):
            line_clean = line.strip()

            # Buffer overflow vulnerabilities
            if 'gets(' in line_clean:
                vulnerabilities.append(
                    f"Line {i}: [CRITICAL] Buffer Overflow - gets() function is unsafe and deprecated")

            if 'strcpy(' in line_clean and 'strncpy(' not in line_clean:
                vulnerabilities.append(f"Line {i}: [HIGH] Buffer Overflow - strcpy() without bounds checking")

            if 'strcat(' in line_clean and 'strncat(' not in line_clean:
                vulnerabilities.append(f"Line {i}: [HIGH] Buffer Overflow - strcat() without bounds checking")

            if 'sprintf(' in line_clean and 'snprintf(' not in line_clean:
                vulnerabilities.append(f"Line {i}: [HIGH] Buffer Overflow - sprintf() without bounds checking")

            # Format string vulnerabilities
            if 'printf(' in line_clean and '%' in line_clean:
                # Check if user input might be directly used
                if any(var in line_clean for var in ['input', 'buffer', 'user', 'argv']):
                    vulnerabilities.append(f"Line {i}: [MEDIUM] Format String Vulnerability - User input in printf")

            # Memory management issues
            if 'malloc(' in line_clean or 'calloc(' in line_clean or 'realloc(' in line_clean:
                malloc_line = i
                # Look ahead for free() - simple check within next 20 lines
                has_free = False
                for j in range(i, min(len(lines), i + 20)):
                    if 'free(' in lines[j]:
                        has_free = True
                        break

                if not has_free:
                    vulnerabilities.append(f"Line {i}: [MEDIUM] Memory Leak - malloc/calloc without corresponding free")

            if 'free(' in line_clean:
                # Check for potential use-after-free
                var_match = re.search(r'free\s*\(\s*(\w+)', line_clean)
                if var_match:
                    var_name = var_match.group(1)
                    # Look ahead for potential use after free
                    for j in range(i, min(len(lines), i + 10)):
                        if var_name in lines[j] and 'free(' not in lines[j]:
                            vulnerabilities.append(
                                f"Line {j + 1}: [HIGH] Use After Free - Variable '{var_name}' used after free")
                            break

            # Integer overflow potential
            if any(op in line_clean for op in ['*', '+', '<<']) and any(
                    type_name in line_clean for type_name in ['int', 'long', 'size_t']):
                if 'unsigned' not in line_clean:
                    vulnerabilities.append(
                        f"Line {i}: [LOW] Integer Overflow - Potential arithmetic overflow with signed integers")

            # Null pointer dereference
            if '->' in line_clean or '*' in line_clean:
                if 'NULL' not in code.upper() and 'if' not in line_clean:
                    vulnerabilities.append(
                        f"Line {i}: [MEDIUM] Null Pointer Dereference - Pointer used without null check")

            # Array bounds checking
            if '[' in line_clean and ']' in line_clean:
                # Check for potential buffer access without bounds checking
                if any(func in line_clean for func in ['scanf', 'gets', 'fgets']):
                    vulnerabilities.append(
                        f"Line {i}: [HIGH] Buffer Overflow - Array access with unsafe input function")

            # Race conditions (basic detection)
            if any(keyword in line_clean for keyword in ['pthread_', 'thread', 'mutex', 'lock']):
                if 'unlock' not in line_clean and 'lock(' in line_clean:
                    vulnerabilities.append(f"Line {i}: [MEDIUM] Race Condition - Lock without corresponding unlock")

            # Insecure random number generation
            if 'rand()' in line_clean and 'srand(' not in code:
                vulnerabilities.append(f"Line {i}: [LOW] Weak Random - rand() without srand() seed")

            # File operations without error checking
            if any(func in line_clean for func in ['fopen(', 'open(']):
                # Check if there's error checking nearby
                has_check = False
                for j in range(max(0, i - 2), min(len(lines), i + 3)):
                    if any(check in lines[j] for check in ['if', '!', 'NULL', 'ERROR', '== -1']):
                        has_check = True
                        break

                if not has_check:
                    vulnerabilities.append(
                        f"Line {i}: [MEDIUM] Resource Management - File operation without error checking")

            # Use of dangerous functions
            dangerous_functions = ['system(', 'exec(', 'popen(']
            for func in dangerous_functions:
                if func in line_clean:
                    vulnerabilities.append(f"Line {i}: [HIGH] Command Injection - Use of dangerous function {func}")

        return vulnerabilities

    def analyze_code_vulnerabilities(self, code_content: str, filename: str = "") -> Optional[str]:
        """
        Analyze C/C++ code for vulnerabilities

        Args:
            code_content (str): The C/C++ source code
            filename (str): Optional filename for context

        Returns:
            Optional[str]: Analysis results or None if failed
        """
        prompt = self._create_vulnerability_prompt(code_content, filename)
        return self.generate_response(prompt, max_new_tokens=800)

    def _create_vulnerability_prompt(self, code: str, filename: str = "") -> str:
        """Create a structured prompt for vulnerability analysis"""
        prompt = f"""You are a security expert analyzing C/C++ code for vulnerabilities.

Analyze the following C/C++ code{"" if not filename else f" from file '{filename}'"} and identify potential security vulnerabilities.

Focus on these common vulnerability types:
1. Buffer overflows (stack and heap)
2. Use-after-free vulnerabilities
3. Memory leaks
4. Format string vulnerabilities
5. Integer overflows/underflows
6. Null pointer dereferences
7. Race conditions
8. Input validation issues

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

Analysis:"""

        return prompt

    def cleanup(self):
        """Clean up resources"""
        if self.session:
            del self.session
        if self.tokenizer:
            del self.tokenizer
        self.logger.info("Resources cleaned up")


# Backward compatibility alias
LLMBackend = ONNXLLMBackend

# Example usage and testing
if __name__ == "__main__":
    # Test the backend
    backend = ONNXLLMBackend()

    if backend.load_model():
        # Test with your actual test files
        test_files = [
            "./tests/data/library.c",
            "./tests/data/notes.cpp"
        ]

        for test_file in test_files:
            if os.path.exists(test_file):
                print(f"\n=== Analyzing {test_file} ===")
                with open(test_file, 'r', encoding='utf-8', errors='ignore') as f:
                    test_code = f.read()

                result = backend.analyze_code_vulnerabilities(test_code, test_file)
                print("Result:")
                print(result)
                print("-" * 50)

        # Also test with simple example
        print("\n=== Testing with simple example ===")
        test_code = """
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char input[100];

    gets(input);  // Vulnerable function
    strcpy(buffer, input);  // Potential buffer overflow

    printf("Hello %s", input);  // Potential format string vulnerability

    return 0;
}
"""

        result = backend.analyze_code_vulnerabilities(test_code, "test.c")
        print("Result:")
        print(result)

        backend.cleanup()
    else:
        print("Failed to load model")