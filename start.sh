#!/usr/bin/env bash
# Exit on error
set -o errexit

# Run the database initialization command
# This ensures the tables are created before the app starts
echo "Running database initialization..."
flask init-db
echo "Database initialization complete."

# Start the Gunicorn web server
echo "Starting Gunicorn server..."
gunicorn --workers 4 --bind 0.0.0.0:10000 app:app

