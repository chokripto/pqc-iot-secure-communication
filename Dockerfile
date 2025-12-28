FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# System deps for building liboqs + python bindings
RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build build-essential pkg-config \
    libssl-dev ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Build and install liboqs
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
  && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
  && ninja -C /tmp/liboqs/build \
  && ninja -C /tmp/liboqs/build install \
  && ldconfig \
  && rm -rf /tmp/liboqs

# Install python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -U pip setuptools wheel \
  && pip install --no-cache-dir -r /app/requirements.txt

# Install liboqs-python (provides: import oqs)
RUN pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git

# Copy project
COPY . /app

# Default command can be overridden by docker-compose
CMD ["python", "-m", "src.server.server_app"]
