FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY config/ config/
COPY data/sample_logs/ data/sample_logs/

RUN pip install --no-cache-dir .

# CLI by default; run the dashboard with:
#   docker run -p 5000:5000 -e DASHBOARD_HOST=0.0.0.0 \
#     --entrypoint python evtx-analyze -m src.dashboard
ENTRYPOINT ["evtx-analyze"]
CMD ["data/sample_logs/security.csv"]
