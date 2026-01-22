# gunicorn.conf.py
import multiprocessing
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '10000')}"
worker_class = 'sync'
workers = 2
threads = 4

timeout = 1200          # 10 minutes
graceful_timeout = 1200
keepalive = 5

limit_request_line = 0
limit_request_field_size = 0

worker_tmp_dir = '/dev/shm'

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

preload_app = False
max_requests = 100
max_requests_jitter = 10
worker_connections = 1000

print("=" * 60)
print("🚀 Gunicorn Configuration Loaded")
print(f"   Workers: {workers}")
print(f"   Worker Class: {worker_class}")
print(f"   Threads: {threads}")
print(f"   Timeout: {timeout}s")
print(f"   Bind: {bind}")
print("=" * 60)