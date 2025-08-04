# Dockerfile

# --- Base Image ---
# Use the official Python 3.10 slim image. It's lightweight and compatible
# with all the required libraries (langchain, streamlit, google-cloud).
FROM python:3.10-slim

# --- Working Directory ---
# Set a working directory inside the container to keep things organized.
WORKDIR /app

# --- Install Dependencies ---
# Copy the requirements file first and install dependencies.
# This leverages Docker's layer caching. If requirements.txt doesn't change,
# this layer will be reused, speeding up future builds significantly.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Copy Application Code ---
# Once dependencies are installed, copy the rest of the application code.
COPY . .

# --- Expose Port (for documentation) ---
# This line documents that the container listens on a port.
# Cloud Run will actually use the $PORT environment variable, not this specific value,
# but it's good practice to include it.
EXPOSE 8080

# --- Runtime Command ---
# This is the command that starts the application.
# It runs streamlit and dynamically uses the $PORT variable provided by Cloud Run.
# The --server.address=0.0.0.0 flag is essential for the container to be
# accessible from outside itself.
CMD streamlit run app.py --server.port=$PORT --server.address=0.0.0.0