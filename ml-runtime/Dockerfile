FROM python:3.12-slim

RUN useradd -m -u 1001 mluser

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY runner.py /app/runner.py
COPY probe_strategies/ /app/probe_strategies/

USER mluser
WORKDIR /app

CMD ["python", "runner.py"]