FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/home/sandbox \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        nodejs \
        npm \
        python3 \
        python3-pip \
        python3-venv \
        python3-setuptools \
        python3-wheel \
        strace \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --home-dir /home/sandbox --shell /bin/bash sandbox \
    && mkdir -p /work /tmp /home/sandbox \
    && chown -R sandbox:sandbox /work /tmp /home/sandbox

COPY entrypoint.sh /usr/local/bin/safeinstall-entrypoint
COPY make_decoys.py /usr/local/bin/make-decoys
RUN ln -s /usr/local/bin/safeinstall-entrypoint /usr/local/bin/safeinstall \
    && chmod 0755 /usr/local/bin/safeinstall-entrypoint /usr/local/bin/make-decoys

USER sandbox
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/safeinstall-entrypoint"]
