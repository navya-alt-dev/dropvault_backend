# gunicorn.conf.py
import os

# Bind to PORT provided by Render
port = os.environ.get('PORT', '10000')
bind = f"0.0.0.0:{port}"

# Workers
workers = 2
worker_class = 'sync'
timeout = 120
keepalive = 5

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'

# Startup
preload_app = True

print(f"🚀 Gunicorn starting on port {port}")