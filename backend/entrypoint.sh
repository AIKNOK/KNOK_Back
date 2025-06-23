#!/bin/bash
set -e

echo "📦 ENVIRONMENT VARIABLES CHECK"
echo "AWS_STORAGE_BUCKET_NAME = $AWS_STORAGE_BUCKET_NAME"
echo "COGNITO_APP_CLIENT_ID = $COGNITO_APP_CLIENT_ID"
echo "AWS_REGION = $AWS_REGION"

echo "🔧 Applying migrations..."
python manage.py migrate --noinput

echo "🚀 Starting Gunicorn..."
exec gunicorn config.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --timeout 120
