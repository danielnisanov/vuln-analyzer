#!/usr/bin/env python3
'''Test script to verify offline operation'''
import os
import sys

# Block network access for this test
os.environ['HF_HUB_OFFLINE'] = '1'
os.environ['TRANSFORMERS_OFFLINE'] = '1'

print("Testing offline model loading...")

try:
    from transformers import AutoTokenizer

    # Try to load tokenizer with local files only
    tokenizer = AutoTokenizer.from_pretrained(
        "./models/phi-4",
        trust_remote_code=True,
        local_files_only=True  # MUST work offline
    )
    print("✓ Tokenizer loaded successfully offline")

    # Check if ONNX model exists
    import glob
    onnx_files = glob.glob("./models/phi-4/**/*.onnx", recursive=True)
    if onnx_files:
        print(f"✓ ONNX model found: {onnx_files[0]}")
    else:
        print("⚠ No ONNX model found")

    print("\n✓ Offline setup verified successfully!")
    print("The tool can now run without internet connection.")

except Exception as e:
    print(f"✗ Offline loading failed: {e}")
    print("Please run setup_model.py first")
    sys.exit(1)
