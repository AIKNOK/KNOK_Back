#!/bin/bash
set -e  # 오류 발생 시 종료

export DJANGO_SETTINGS_MODULE=config.settings

echo "🔄 Applying migrations..."
python manage.py migrate

echo "🚀 Starting Gunicorn..."
exec gunicorn config.wsgi:application --bind 0.0.0.0:8000
