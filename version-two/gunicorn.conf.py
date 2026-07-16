# Gunicorn configuration for Aegis SCADA v2
import os

bind = os.environ.get("AEGIS_BIND", "127.0.0.1:5000")
workers = int(os.environ.get("AEGIS_WORKERS", "4"))
timeout = int(os.environ.get("AEGIS_TIMEOUT", "30"))
loglevel = os.environ.get("AEGIS_LOGLEVEL", "info")
accesslog = "-"
errorlog = "-"
