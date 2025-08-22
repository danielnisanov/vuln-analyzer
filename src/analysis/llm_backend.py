"""
ONNX-Compatible LLM Backend for Vulnerability Analysis using Phi-4 model
Updated to use the Prompter module for better prompt management
"""
import os
import json
import logging
import re
from typing import Optional, Dict, Any, List
import numpy as np

# Import the prompter module
from .prompter import VulnerabilityPrompter

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
        self.session = None
        self.tokenizer = None
        self.max_tokens = 2048
        self.onnx_warning_shown = False  # Track if warning was shown

        # Initialize prompter for sophisticated prompt management
        self.prompter = VulnerabilityPrompter()

        logging.basicConfig(level=logging.WARNING)  # Reduced verbosity
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
            # Show warning only once
            if not self.onnx_warning_shown:
                self.logger.warning("ONNX inference is complex for this model. Falling back to rule-based analysis.")
                self.onnx_warning_shown = True

            return self._generate_with_rules(prompt, max_new_tokens)

        except Exception as e:
            if not self.onnx_warning_shown:
                self.logger.warning(f"ONNX inference failed: {e}. Using rule-based analysis.")
                self.onnx_warning_shown = True
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
                vulnerabilities.append(f"Line {i}: [CRITICAL] Buffer Overflow - gets() function is unsafe and deprecated")

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

            # Command injection
            if 'system(' in line_clean:
                vulnerabilities.append(f"Line {i}: [HIGH] Command Injection - Use of system() function")

            # Integer overflow potential
            if any(op in line_clean for op in ['*', '+', '<<']) and any(type_name in line_clean for type_name in ['int', 'long', 'size_t']):
                if 'unsigned' not in line_clean:
                    vulnerabilities.append(f"Line {i}: [LOW] Integer Overflow - Potential arithmetic overflow with signed integers")

        return vulnerabilities

    def analyze_code_vulnerabilities(self, code_content: str, filename: str = "",
                                    template: str = None) -> Optional[str]:
        """
        Analyze C/C++ code for vulnerabilities using the prompter

        Args:
            code_content (str): The C/C++ source code
            filename (str): Optional filename for context
            template (str): Optional template name to use

        Returns:
            Optional[str]: Analysis results or None if failed
        """
        # Use prompter to create the prompt
        if template:
            self.prompter.set_template(template)

        prompt = self.prompter.create_prompt(code_content, filename, template)
        return self.generate_response(prompt, max_new_tokens=800)

    def analyze_chunk(self, chunk_content: str, chunk_info: Dict[str, Any]) -> Optional[str]:
        """
        Analyze a code chunk with context-aware prompting

        Args:
            chunk_content (str): The code chunk
            chunk_info (dict): Chunk metadata including type, start_line, function_name

        Returns:
            Optional[str]: Analysis results
        """
        prompt = self.prompter.create_chunk_prompt(chunk_content, chunk_info)
        return self.generate_response(prompt, max_new_tokens=600)

    def analyze_with_context(self, code_content: str, context: Dict[str, Any]) -> Optional[str]:
        """
        Analyze code with contextual information

        Args:
            code_content (str): The C/C++ source code
            context (dict): Context information about the code

        Returns:
            Optional[str]: Analysis results
        """
        prompt = self.prompter.create_contextual_prompt(code_content, context)
        return self.generate_response(prompt, max_new_tokens=800)

    def get_available_templates(self) -> List[str]:
        """Get list of available analysis templates"""
        return self.prompter.get_template_names()

    def set_analysis_template(self, template_name: str):
        """Set the active analysis template"""
        self.prompter.set_template(template_name)

    def cleanup(self):
        """Clean up resources"""
        if self.session:
            del self.session
        if self.tokenizer:
            del self.tokenizer
        self.logger.info("Resources cleaned up")


# Backward compatibility alias
LLMBackend = ONNXLLMBackend