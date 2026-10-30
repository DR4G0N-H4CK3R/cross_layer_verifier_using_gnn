# Verification-host image (Raspberry Pi 4/5, arm64, or x86-64 for development).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tshark && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
VOLUME ["/app/state", "/app/sample_data"]
EXPOSE 8000
# default: simulated testbed replay with dashboard; override for real captures:
#   docker run -v $PWD/captures:/cap gwverify python scripts/verify_capture.py verify --radio /cap/r.pcap --ip /cap/ip.pcap --gateway-ip 192.168.10.2
CMD ["python", "simulator_main.py", "--scenario", "mixed", "--port", "8000"]
