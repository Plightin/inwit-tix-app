#!/usr/bin/env bash
# Exit on error
set -o errexit

# A loop to wait for the database to be ready
# It will try 5 times with a 5-second delay between attempts.
n=0
until [ "$n" -ge 5 ]
do
   echo "Running database initialization (Attempt $((n+1)))..."
   # Use python -m flask to be explicit
   python -m flask init-db && break  # attempt to initialize and exit loop if successful
   n=$((n+1))
   echo "Database not ready, waiting 5 seconds..."
   sleep 5
done

# Check if the loop finished because of success or timeout
if [ "$n" -ge 5 ]; then
    echo "Could not connect to the database after several attempts. Exiting."
    exit 1
fi

echo "Database initialization complete."

# Start the Gunicorn web server
echo "Starting Gunicorn server..."
gunicorn --workers 4 --bind 0.0.0.0:10000 app:app
