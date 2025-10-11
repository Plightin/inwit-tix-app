#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies from your requirements file
pip install -r requirements.txt

# Run the database initialization command defined in app.py
flask init-db

