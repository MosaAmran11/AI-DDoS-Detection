"""
Wrapper to run the realtime detector from the workspace root.
It adjusts sys.path so that the nested `AI-DDoS-Detection-main` folder modules import cleanly.
"""
import os
import sys

THIS_DIR = os.path.dirname(__file__)
NESTED = os.path.join(THIS_DIR, 'AI-DDoS-Detection-main')
if os.path.isdir(NESTED) and NESTED not in sys.path:
    sys.path.insert(0, NESTED)

try:
    import realtime_transformer_detector_v2 as detector
except Exception as e:
    print('Failed to import realtime_transformer_detector_v2 from nested folder:', e)
    raise

if __name__ == '__main__':
    # The detector script exposes main(); call it to start threads
    if hasattr(detector, 'main'):
        detector.main()
    else:
        print('detector module has no main() entrypoint')
