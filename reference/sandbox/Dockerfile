# Sandbox image for the reproducer and patcher nodes.
# Built once by an operator — never by an agent.
FROM python:3.13.18-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

# The sandbox has no network (Network.none()), so nothing can be installed at
# run time. Add your target's dependencies here.
RUN apt-get update \
 && apt-get install -y --no-install-recommends patch \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --require-hashes --no-cache-dir -r requirements.txt

WORKDIR /workspace
