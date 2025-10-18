# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies, including dos2unix to fix line endings
RUN apt-get update && apt-get install -y \
    dos2unix \
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

# Set the FLASK_APP environment variable inside the container
ENV FLASK_APP="app:app"

# Copy the startup script, fix line endings, and make it executable
COPY start.sh .
RUN dos2unix ./start.sh
RUN chmod +x ./start.sh

# Expose the port the app runs on
EXPOSE 10000

# Use the startup script as the main command to start the application
CMD ["./start.sh"]
