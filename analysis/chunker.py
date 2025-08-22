"""
Code Chunker for handling large C/C++ files
Breaks down code into manageable chunks while preserving context
"""
import re
from typing import List, Tuple, Dict
from dataclasses import dataclass


@dataclass
class CodeChunk:
    """Represents a chunk of code with metadata"""
    content: str
    start_line: int
    end_line: int
    chunk_type: str  # 'function', 'global', 'includes', 'mixed'
    function_name: str = ""


class CodeChunker:
    """
    Handles chunking of C/C++ code files for analysis
    """

    def __init__(self, max_chunk_size: int = 1500):
        """
        Initialize the chunker

        Args:
            max_chunk_size (int): Maximum characters per chunk
        """
        self.max_chunk_size = max_chunk_size

        # Regex patterns for C/C++ constructs
        self.function_pattern = re.compile(
            r'^\s*(?:(?:static|inline|extern)\s+)*(?:\w+\s+)*\*?\s*(\w+)\s*\([^)]*\)\s*\{',
            re.MULTILINE
        )

        self.include_pattern = re.compile(r'^\s*#\s*include\s*[<"][^>"]*[>"]', re.MULTILINE)
        self.define_pattern = re.compile(r'^\s*#\s*define\s+\w+', re.MULTILINE)
        self.comment_pattern = re.compile(r'(/\*.*?\*/|//.*?$)', re.DOTALL | re.MULTILINE)

    def chunk_file(self, file_content: str) -> List[CodeChunk]:
        """
        Break down a file into logical chunks

        Args:
            file_content (str): The complete file content

        Returns:
            List[CodeChunk]: List of code chunks
        """
        lines = file_content.split('\n')
        chunks = []

        # First, extract includes and defines (usually at the top)
        includes_chunk = self._extract_includes_and_defines(file_content)
        if includes_chunk:
            chunks.append(includes_chunk)

        # Extract functions
        function_chunks = self._extract_functions(file_content, lines)
        chunks.extend(function_chunks)

        # Handle remaining global code
        global_chunk = self._extract_global_code(file_content, function_chunks)
        if global_chunk:
            chunks.append(global_chunk)

        # If chunks are too large, split them further
        final_chunks = []
        for chunk in chunks:
            if len(chunk.content) > self.max_chunk_size:
                sub_chunks = self._split_large_chunk(chunk)
                final_chunks.extend(sub_chunks)
            else:
                final_chunks.append(chunk)

        return final_chunks

    def _extract_includes_and_defines(self, content: str) -> CodeChunk:
        """Extract #include and #define statements"""
        includes = []
        defines = []

        for match in self.include_pattern.finditer(content):
            includes.append(match.group())

        for match in self.define_pattern.finditer(content):
            # Get the full line
            line_start = content.rfind('\n', 0, match.start()) + 1
            line_end = content.find('\n', match.end())
            if line_end == -1:
                line_end = len(content)
            defines.append(content[line_start:line_end])

        if includes or defines:
            combined = '\n'.join(includes + defines)
            return CodeChunk(
                content=combined,
                start_line=1,
                end_line=len(combined.split('\n')),
                chunk_type='includes'
            )

        return None

    def _extract_functions(self, content: str, lines: List[str]) -> List[CodeChunk]:
        """Extract individual functions"""
        chunks = []

        # Find function definitions
        for match in self.function_pattern.finditer(content):
            func_name = match.group(1)
            func_start = match.start()

            # Find the matching closing brace
            func_content, func_end = self._extract_function_body(content, func_start)

            if func_content:
                # Calculate line numbers
                start_line = content[:func_start].count('\n') + 1
                end_line = content[:func_end].count('\n') + 1

                chunks.append(CodeChunk(
                    content=func_content.strip(),
                    start_line=start_line,
                    end_line=end_line,
                    chunk_type='function',
                    function_name=func_name
                ))

        return chunks

    def _extract_function_body(self, content: str, start_pos: int) -> Tuple[str, int]:
        """
        Extract complete function body by matching braces

        Args:
            content (str): Full file content
            start_pos (int): Position where function starts

        Returns:
            Tuple[str, int]: (function_content, end_position)
        """
        # Find the opening brace
        brace_pos = content.find('{', start_pos)
        if brace_pos == -1:
            return None, -1

        # Count braces to find matching closing brace
        brace_count = 1
        pos = brace_pos + 1
        in_string = False
        in_char = False
        in_comment = False

        while pos < len(content) and brace_count > 0:
            char = content[pos]

            # Handle string literals
            if char == '"' and not in_char and not in_comment:
                if pos == 0 or content[pos - 1] != '\\':
                    in_string = not in_string
            elif char == "'" and not in_string and not in_comment:
                if pos == 0 or content[pos - 1] != '\\':
                    in_char = not in_char

            # Handle comments
            elif content[pos:pos + 2] == '/*' and not in_string and not in_char:
                in_comment = True
                pos += 1  # Skip next character
            elif content[pos:pos + 2] == '*/' and in_comment:
                in_comment = False
                pos += 1  # Skip next character
            elif content[pos:pos + 2] == '//' and not in_string and not in_char and not in_comment:
                # Skip to end of line
                pos = content.find('\n', pos)
                if pos == -1:
                    break
                pos -= 1  # Will be incremented at end of loop

            # Count braces only if not in string/char/comment
            elif not in_string and not in_char and not in_comment:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1

            pos += 1

        if brace_count == 0:
            # Find the start of the function (including return type and name)
            func_start = start_pos
            while func_start > 0 and content[func_start - 1] not in '\n;{}':
                func_start -= 1

            return content[func_start:pos], pos

        return None, -1

    def _extract_global_code(self, content: str, function_chunks: List[CodeChunk]) -> CodeChunk:
        """Extract global variables, structs, and other non-function code"""
        # Remove includes/defines and functions from content
        remaining_content = content

        # Remove function bodies
        for chunk in function_chunks:
            if chunk.chunk_type == 'function':
                remaining_content = remaining_content.replace(chunk.content, '')

        # Remove includes/defines
        remaining_content = self.include_pattern.sub('', remaining_content)
        remaining_content = self.define_pattern.sub('', remaining_content)

        # Clean up empty lines and whitespace
        lines = [line for line in remaining_content.split('\n') if line.strip()]

        if lines:
            global_content = '\n'.join(lines)
            return CodeChunk(
                content=global_content,
                start_line=1,  # Would need more sophisticated line tracking
                end_line=len(lines),
                chunk_type='global'
            )

        return None

    def _split_large_chunk(self, chunk: CodeChunk) -> List[CodeChunk]:
        """Split a chunk that's too large into smaller pieces"""
        if len(chunk.content) <= self.max_chunk_size:
            return [chunk]

        chunks = []
        lines = chunk.content.split('\n')
        current_chunk = []
        current_size = 0
        current_line = chunk.start_line

        for i, line in enumerate(lines):
            line_size = len(line) + 1  # +1 for newline

            if current_size + line_size > self.max_chunk_size and current_chunk:
                # Create chunk from current buffer
                chunk_content = '\n'.join(current_chunk)
                chunks.append(CodeChunk(
                    content=chunk_content,
                    start_line=current_line,
                    end_line=current_line + len(current_chunk) - 1,
                    chunk_type='mixed',
                    function_name=chunk.function_name
                ))

                # Start new chunk
                current_chunk = [line]
                current_size = line_size
                current_line = chunk.start_line + i
            else:
                current_chunk.append(line)
                current_size += line_size

        # Add remaining chunk
        if current_chunk:
            chunk_content = '\n'.join(current_chunk)
            chunks.append(CodeChunk(
                content=chunk_content,
                start_line=current_line,
                end_line=current_line + len(current_chunk) - 1,
                chunk_type='mixed',
                function_name=chunk.function_name
            ))

        return chunks

    def get_chunk_info(self, chunks: List[CodeChunk]) -> Dict:
        """Get summary information about chunks"""
        info = {
            'total_chunks': len(chunks),
            'chunk_types': {},
            'functions': [],
            'avg_chunk_size': 0
        }

        total_size = 0
        for chunk in chunks:
            # Count chunk types
            chunk_type = chunk.chunk_type
            info['chunk_types'][chunk_type] = info['chunk_types'].get(chunk_type, 0) + 1

            # Collect function names
            if chunk.function_name:
                info['functions'].append(chunk.function_name)

            total_size += len(chunk.content)

        info['avg_chunk_size'] = total_size // len(chunks) if chunks else 0

        return info


# Example usage
if __name__ == "__main__":
    chunker = CodeChunker(max_chunk_size=800)

    test_code = """
#include <stdio.h>
#include <string.h>

#define MAX_SIZE 100

int global_var = 0;

struct Point {
    int x, y;
};

int add(int a, int b) {
    return a + b;
}

void vulnerable_function() {
    char buffer[10];
    gets(buffer);  // Vulnerable
}

int main() {
    printf("Hello World\\n");
    return 0;
}
"""

    chunks = chunker.chunk_file(test_code)

    print("Chunking Results:")
    for i, chunk in enumerate(chunks):
        print(f"Chunk {i + 1}: {chunk.chunk_type} ({len(chunk.content)} chars)")
        if chunk.function_name:
            print(f"  Function: {chunk.function_name}")
        print(f"  Lines: {chunk.start_line}-{chunk.end_line}")
        print(f"  Content preview: {chunk.content[:100]}...")
        print()

    info = chunker.get_chunk_info(chunks)
    print("Summary:", info)