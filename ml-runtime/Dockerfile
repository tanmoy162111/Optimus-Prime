FROM python:3.12-slim

WORKDIR /app

# ML Runtime — ART, Promptfoo, model audit tools
# network_mode: none — verified on each compose change
RUN pip install --no-cache-dir adversarial-robustness-toolbox numpy scipy

COPY ml-runtime/ /app/

CMD ["python", "runner.py"]
