# /cloud-run-vt-summarizer/Dockerfile

# Use the official Python 3.10 slim image as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# Use --no-cache-dir to reduce image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code to the working directory
COPY . .

# EXPOSE is now just for documentation; Cloud Run ignores it and uses the PORT env var.
EXPOSE 8080

# --- CORRECTED CMD INSTRUCTION ---
# Use the shell form of CMD to dynamically use the $PORT variable set by Cloud Run.
# Streamlit will now listen on whatever port Cloud Run assigns (e.g., 8080).
CMD streamlit run app.py --server.port=$PORT --server.address=0.0.0.0