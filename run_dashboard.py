"""
Wrapper to run the dashboard application from the workspace root.
This avoids accidental duplicated paths when invoking Python from the workspace root.
"""
import os
import sys

THIS_DIR = os.path.dirname(__file__)
NESTED = os.path.join(THIS_DIR, 'AI-DDoS-Detection-main')
if os.path.isdir(NESTED) and NESTED not in sys.path:
    sys.path.insert(0, NESTED)

try:
    # Prefer the clean dashboard implementation if present
    from dashboard_app_clean import app
except Exception:
    try:
        from dashboard_app import app
    except Exception as e:
        print('Failed to import dashboard_app (_clean_) from nested folder:', e)
        raise

if __name__ == '__main__':
    # Run Flask app with environment-configurable host/port/debug
    host = os.getenv('DASH_HOST', '0.0.0.0')
    port = int(os.getenv('DASH_PORT', '5000'))
    debug = os.getenv('DASH_DEBUG', 'False').lower() in ('1', 'true', 'yes')
    app.run(host=host, port=port, debug=debug)
