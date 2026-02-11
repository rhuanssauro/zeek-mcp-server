FROM zeek/zeek:latest

LABEL maintainer="rhuanssauro"
LABEL description="Zeek MCP Server - PCAP analysis and network security monitoring"

# Install Python and pip
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        tini && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 mcpuser && \
    useradd -u 1000 -g mcpuser -m -s /bin/bash mcpuser

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip3 install --no-cache-dir --break-system-packages \
    "mcp>=1.26.0" \
    "pydantic>=2.0.0" \
    "pydantic-settings>=2.0.0"

# Copy application code
COPY server.py zeek_parser.py ./

# Create mount point directories
RUN mkdir -p /app/pcaps /app/output /app/scripts && \
    chown -R mcpuser:mcpuser /app

# Copy default scripts
COPY scripts/ /app/default-scripts/
RUN chown -R mcpuser:mcpuser /app/default-scripts

# Environment
ENV ZEEK_PCAP_DIR=/app/pcaps
ENV ZEEK_OUTPUT_DIR=/app/output
ENV ZEEK_SCRIPTS_DIR=/app/scripts
ENV ZEEK_MAX_PCAP_MB=500
ENV ZEEK_TIMEOUT=300

# Switch to non-root (Zeek needs root for live capture, but not PCAP analysis)
USER mcpuser

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD zeek --version > /dev/null 2>&1 && python3 -c "import mcp" > /dev/null 2>&1

ENTRYPOINT ["tini", "--"]
CMD ["python3", "/app/server.py"]
