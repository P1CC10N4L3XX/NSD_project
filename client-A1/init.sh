#!/bin/sh
# client-A1 (Site 1) — avvio del servizio con AppArmor in enforce mode
set -eu


ip link set lo up
ip link set eth0 up

ip addr add 192.168.3.2/24 dev eth0

# securityfs non e' montata nei container di default: serve per parlare
# con il LSM del kernel (il nodo GNS3 e' privileged)
if [ ! -d /sys/kernel/security/apparmor ]; then
    mount -t securityfs securityfs /sys/kernel/security
fi

# carica/aggiorna il profilo: il parser carica in ENFORCE di default
# (-r = replace: ricarica anche se il profilo esiste gia')
apparmor_parser -r /etc/apparmor.d/client-a1-app

# avvia il servizio CONFINATO nel profilo nominato
mkdir -p /var/log
(aa-exec -p client-a1-app -- python3 /opt/client-a1/app.py \
    >> /var/log/client-a1-app.log 2>&1 &)

# evidenza per il report (AppArmor enabled and active)
aa-status > /root/aa-status.txt || true

echo "[client-A1] profilo 'client-a1-app' caricato (enforce), servizio su :8080"
