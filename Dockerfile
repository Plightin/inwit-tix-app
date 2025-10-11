# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required by WeasyPrint for PDF generation
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application's code to the working directory
COPY . .

# Set the FLASK_APP environment variable
ENV FLASK_APP="app:app"

# Expose the port the app runs on
EXPOSE 10000

# Define the command to run your app using Gunicorn
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:10000", "--limit-request-field-size", "0", "app:app"]

