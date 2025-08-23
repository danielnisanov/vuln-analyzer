import sys
import time
import onnxruntime_genai as og

MODEL_DIR = "models/phi-4/cpu_and_mobile/cpu-int4-rtn-block-32-acc-level-4"

print("[TEST] Trying to load model from:", MODEL_DIR)
t0 = time.time()

try:
    print("[TEST] Creating Config ...")
    cfg = og.Config(MODEL_DIR)
    print("[TEST] Config OK (%.2fs)" % (time.time() - t0))

    print("[TEST] Creating Model ...")
    model = og.Model(cfg)
    print("[TEST] Model OK (%.2fs)" % (time.time() - t0))

    print("[TEST] Creating Tokenizer ...")
    tok = og.Tokenizer(model)
    print("[TEST] Tokenizer OK (%.2fs)" % (time.time() - t0))

    print("[TEST] All components loaded successfully ✅")

except Exception as e:
    print("[TEST] ERROR:", e)
    sys.exit(1)
