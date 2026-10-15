#!/usr/bin/env bash
# Génère des exécutions bénignes et suspectes pour tester execsentry.
# À lancer dans un terminal pendant que l'agent tourne en root.
set -u

echo "[demo] exécution bénigne : /bin/true"
/bin/true

echo "[demo] exécution SUSPICIOUS : /tmp/execsentry-demo"
cp /bin/true /tmp/execsentry-demo
/tmp/execsentry-demo

echo "[demo] exécution CRITICAL : /dev/shm/nc (binaire à double usage en chemin volatil)"
printf '#!/bin/sh\nexit 0\n' > /dev/shm/nc
chmod +x /dev/shm/nc
/dev/shm/nc

echo "[demo] nettoyage"
rm -f /tmp/execsentry-demo /dev/shm/nc
