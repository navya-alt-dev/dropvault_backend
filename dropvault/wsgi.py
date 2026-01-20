# dropvault/wsgi.py
import os
import sys

# Add project to path
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dropvault.settings')

from django.core.wsgi import get_wsgi_application

print("🚀 WSGI application starting...")
application = get_wsgi_application()
print("✅ WSGI application loaded successfully")