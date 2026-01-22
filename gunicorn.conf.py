# gunicorn.conf.py
import multiprocessing
import os

# Bind to Render's port
bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"

# ✅ Use sync workers (no gevent needed)
worker_class = 'sync'

# ✅ Workers and threads (optimized for Render free tier)
workers = 2  # Keep low for 512MB RAM limit
threads = 4  # Add threading for concurrent requests

# ✅ CRITICAL: Timeouts for large file uploads
timeout = 600           # 10 minutes
graceful_timeout = 600
keepalive = 5

# ✅ Request size limits (unlimited for large uploads)
limit_request_line = 0
limit_request_field_size = 0

# ✅ Use RAM disk for temporary files (faster on Render)
worker_tmp_dir = '/dev/shm'

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# ✅ Don't preload app (better for file uploads)
preload_app = False

# ✅ Restart workers after N requests (prevent memory leaks)
max_requests = 100
max_requests_jitter = 10

# ✅ Worker connections (for handling concurrent uploads)
worker_connections = 1000

print("=" * 60)
print("🚀 Gunicorn Configuration Loaded")
print(f"   Workers: {workers}")
print(f"   Worker Class: {worker_class}")
print(f"   Threads: {threads}")
print(f"   Timeout: {timeout}s")
print(f"   Bind: {bind}")
print("=" * 60)