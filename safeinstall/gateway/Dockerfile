FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir pyyaml

COPY proxy.py /opt/safeinstall/proxy.py
COPY dns_server.py /opt/safeinstall/dns_server.py
COPY dnsmasq.conf /opt/safeinstall/dnsmasq.conf

EXPOSE 3128
EXPOSE 53/udp

CMD ["python", "/opt/safeinstall/proxy.py"]
