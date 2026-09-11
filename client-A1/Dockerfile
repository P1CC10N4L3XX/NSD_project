FROM nsdcourse/basenet:latest

# strumenti userspace AppArmor (l'enforcement resta a carico del kernel
# della VM host, condiviso dal container) + utility di montaggio
RUN apt-get update && apt-get install -y --no-install-recommends \
        apparmor \
        apparmor-utils \
        util-linux \
        curl \
    && rm -rf /var/lib/apt/lists/*

# servizio da confinare + dati
COPY app/app.py /opt/client-a1/app.py
COPY data/status.txt /opt/client-a1/data/status.txt

# profilo AppArmor (verra' caricato in enforce da init.sh)
COPY apparmor/client-a1-app /etc/apparmor.d/client-a1-app

COPY init.sh /root/init.sh
RUN chmod +x /root/init.sh && mkdir -p /var/log /opt/client-a1/data
