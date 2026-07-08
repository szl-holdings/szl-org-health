# Thin container for szl-org-health. Stdlib-only backend; serves the dashboard
# UI and the live /api/health aggregate on the HF Space app_port.
FROM python:3.12-slim
WORKDIR /app
COPY . /app
EXPOSE 7860
CMD ["python", "app.py"]
