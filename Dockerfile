FROM python:3.12-slim

# openssl is only needed for the dashboard's self-signed HTTPS cert
# (fan_control.py shells out to the openssl CLI to generate it).
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask requests cheroot

WORKDIR /app
COPY fan_control.py .

# config.json / history.json / tls/ all live under /srv/ilo-fan-control
# regardless of where the script itself runs from -- mount your data
# directory there to persist them across container restarts/upgrades.
VOLUME ["/srv/ilo-fan-control"]

EXPOSE 5000

ENTRYPOINT ["python3", "fan_control.py"]
