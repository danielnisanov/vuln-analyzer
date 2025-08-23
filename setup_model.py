#!/usr/bin/env python3
"""
Setup script for downloading and preparing the Phi-4 model for offline use
Run this ONCE with internet connection to prepare the model for offline operation
"""

import os
import sys
import shutil
from pathlib import Path


def check_internet():
    """Check if internet connection is available"""
    import urllib.request
    try:
        urllib.request.urlopen('http://www.google.com', timeout=5)
        return True
    except:
        return False


def setup_model():
    """Download and setup Phi-4 model for offline use"""

    print("=" * 60)
    print("Phi-4 Model Setup for Offline Vulnerability Analysis")
    print("=" * 60)
    print("\nThis script will download the necessary model files.")
    print("Run this ONCE with internet connection.")
    print("After setup, the tool will work completely offline.\n")

    # Check internet
    if not check_internet():
        print("ERROR: No internet connection detected.")
        print("This setup script requires internet to download model files.")
        print("After setup is complete, the tool will work offline.")
        return False

    model_dir = Path("./models/phi-4")
    model_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Install required packages if not present
    print("Step 1: Checking required packages...")
    try:
        import transformers
        import onnxruntime
        print("✓ Required packages found")
    except ImportError:
        print("Installing required packages...")
        os.system("pip install transformers onnxruntime onnxruntime-genai")

    # Step 2: Download tokenizer files
    print("\nStep 2: Downloading tokenizer files...")
    try:
        from transformers import AutoTokenizer

        # Download tokenizer with all files
        print("Downloading from microsoft/phi-4...")
        tokenizer = AutoTokenizer.from_pretrained(
            "microsoft/phi-4",
            trust_remote_code=True,
            local_files_only=False  # Allow download for setup
        )

        # Save tokenizer locally
        tokenizer.save_pretrained(str(model_dir))
        print(f"✓ Tokenizer saved to {model_dir}")

        # Verify files exist
        required_files = [
            "tokenizer.json",
            "tokenizer_config.json",
            "special_tokens_map.json"
        ]

        missing_files = []
        for file in required_files:
            if not (model_dir / file).exists():
                missing_files.append(file)

        if missing_files:
            print(f"Warning: Some tokenizer files may be missing: {missing_files}")
            print("The tool may still work with available files.")
        else:
            print("✓ All tokenizer files downloaded successfully")

    except Exception as e:
        print(f"ERROR downloading tokenizer: {e}")
        return False

    # Step 3: Check for ONNX model
    print("\nStep 3: Checking for ONNX model files...")

    # Look for ONNX files
    onnx_files = list(model_dir.rglob("*.onnx"))

    if not onnx_files:
        print("\n⚠ ONNX model files not found!")
        print("\nTo complete setup, you need to:")
        print("1. Download the ONNX model from Hugging Face or Microsoft")
        print("2. Place the .onnx file in the models/phi-4 directory")
        print("\nFor CPU inference, look for quantized versions like:")
        print("  - cpu-int4-rtn-block-32-acc-level-4/model.onnx")
        print("\nYou can download from:")
        print("  https://huggingface.co/microsoft/phi-4")
    else:
        print(f"✓ Found ONNX model: {onnx_files[0]}")

        # Check for genai_config.json if using onnxruntime-genai
        genai_config = onnx_files[0].parent / "genai_config.json"
        if not genai_config.exists():
            print("Note: genai_config.json not found. Creating basic config...")
            # Create a basic genai_config.json
            import json
            config = {
                "model": {
                    "decoder": {
                        "session_options": {
                            "provider_options": [
                                {
                                    "CPUExecutionProvider": {}
                                }
                            ]
                        }
                    }
                }
            }
            with open(genai_config, 'w') as f:
                json.dump(config, f, indent=2)

    # Step 4: Create offline verification script
    print("\nStep 4: Creating offline test script...")

    test_script = """#!/usr/bin/env python3
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

    print("\\n✓ Offline setup verified successfully!")
    print("The tool can now run without internet connection.")

except Exception as e:
    print(f"✗ Offline loading failed: {e}")
    print("Please run setup_model.py first")
    sys.exit(1)
"""

    with open("test_offline.py", "w", encoding="utf-8") as f:
        f.write(test_script)

    print("✓ Created test_offline.py")

    # Step 5: Summary
    print("\n" + "=" * 60)
    print("Setup Summary:")
    print("=" * 60)

    if onnx_files:
        print("✓ Model setup complete!")
        print("\nTo verify offline operation, run:")
        print("  python test_offline.py")
        print("\nThe tool will now work without internet connection.")
    else:
        print("⚠ Setup partially complete")
        print("  - Tokenizer files downloaded")
        print("  - ONNX model files need to be added manually")
        print("\nComplete setup by placing ONNX files in models/phi-4/")

    return True


if __name__ == "__main__":
    success = setup_model()
    sys.exit(0 if success else 1)