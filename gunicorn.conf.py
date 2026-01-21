# gunicorn.conf.py
import multiprocessing
import os

# Bind
bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"

# ✅ Worker settings
worker_class = 'sync'  # Use sync for Render free tier
workers = 2  # Low for free tier
threads = 4  # Add threading

# ✅ CRITICAL: Timeouts
timeout = 600           # 10 minutes
graceful_timeout = 600
keepalive = 5

# ✅ Request limits
limit_request_line = 0
limit_request_field_size = 0

# ✅ Worker temp dir (use RAM disk)
worker_tmp_dir = '/dev/shm'

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# ✅ Prevent preload
preload_app = False

# ✅ Worker recycling
max_requests = 100
max_requests_jitter = 10

print("🚀 Gunicorn Config Loaded")
print(f"   Workers: {workers}")
print(f"   Timeout: {timeout}s")
print(f"   Threads: {threads}")