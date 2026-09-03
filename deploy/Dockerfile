# APIP public-beta controller image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APIP_CONFIG=/etc/apip/apip.toml

WORKDIR /opt/apip

# Build catalog first so dependency layers cache.
COPY pyproject.toml README.md PRODUCT.md ./
COPY src ./src
COPY deploy/config/apip.toml.example ./deploy/config/apip.toml.example

RUN pip install --no-cache-dir .

# Example config the operator is expected to replace.
RUN mkdir -p /etc/apip /var/lib/apip/rpz \
 && cp deploy/config/apip.toml.example /etc/apip/apip.toml

VOLUME ["/var/lib/apip/rpz"]
EXPOSE 8510

HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
  CMD apip status --base http://127.0.0.1:8510 || exit 1

ENTRYPOINT ["apip"]