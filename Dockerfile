FROM python:3.12-slim

LABEL org.opencontainers.image.title="CredWatch" \
      org.opencontainers.image.description="云上凭据泄露自动化检测平台（防御性安全研究工具）" \
      org.opencontainers.image.version="1.0.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    CREDWATCH_DB=/app/data/credwatch.db

WORKDIR /app

# 依赖先拷贝，利用镜像层缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir streamlit

COPY credwatch/ ./credwatch/
COPY config/ ./config/
COPY docs/ ./docs/
COPY demo/ ./demo/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY README.md ./

RUN mkdir -p /app/data /app/output /samples

# 以非 root 用户运行（防御性工具自身也应当遵循最小权限原则）
RUN useradd --create-home --shell /bin/bash credwatch \
 && chown -R credwatch:credwatch /app
USER credwatch

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
  CMD python -c "import credwatch, sys; sys.exit(0 if credwatch.__version__ else 1)"

ENTRYPOINT ["python", "-m", "credwatch"]
CMD ["init"]
