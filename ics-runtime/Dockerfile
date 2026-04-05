FROM python:3.12-slim

WORKDIR /app

# ICS Runtime — pymodbus, python-snap7, scapy, plcscan
# network_mode: none by default. Operator enables target interface via scope.yaml.
RUN pip install --no-cache-dir pymodbus scapy

COPY ics-runtime/ /app/

CMD ["python", "runner.py"]
