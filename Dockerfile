# Thin container for szl-org-health; the multi-architecture base index is pinned.
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.txt
COPY app.py /app/app.py
COPY census/__init__.py /app/census/__init__.py
COPY census/common.py /app/census/common.py
COPY census/github.py /app/census/github.py
COPY census/github_ci.py /app/census/github_ci.py
COPY census/head_ci.py /app/census/head_ci.py
COPY census/github_inventory.py /app/census/github_inventory.py
COPY census/governance.py /app/census/governance.py
COPY census/huggingface.py /app/census/huggingface.py
COPY census/space_readiness.py /app/census/space_readiness.py
COPY census/vertical_contracts.py /app/census/vertical_contracts.py
COPY census/report.py /app/census/report.py
COPY census/portal_projection.py /app/census/portal_projection.py
COPY census/system_design.py /app/census/system_design.py
COPY census/proof_graph.py /app/census/proof_graph.py
COPY census/sites.py /app/census/sites.py
COPY governance/policy.json /app/governance/policy.json
COPY static/index.html /app/static/index.html
COPY static/proof-graph.html /app/static/proof-graph.html
COPY static/data.json /app/static/data.json
EXPOSE 7860
USER 65532:65532
CMD ["python", "app.py"]
