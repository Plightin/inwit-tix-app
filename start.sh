#!/usr/bin/env bash
# Exit on error
set -o errexit

# Run the database initialization command
echo "Running database initialization..."
flask init-db
echo "Database initialization complete."

# Start the Gunicorn web server
echo "Starting Gunicorn server..."
# UPDATED: Removed the '--limit-request-field-size 0' argument to ensure compatibility.
gunicorn --workers 4 --bind 0.0.0.0:10000 app:app

