FROM python:3.12-slim

LABEL maintainer="Zilinlin <shenzilin27@gmail.com>"
LABEL description="Security auditing tool for OpenClaw deployments"
LABEL org.opencontainers.image.source="https://github.com/Zilinlin/openclaw-security-auditor"
LABEL org.opencontainers.image.license="MIT"

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir .

RUN useradd --create-home --shell /bin/bash auditor
USER auditor

ENTRYPOINT ["openclaw-audit"]
CMD ["--help"]
