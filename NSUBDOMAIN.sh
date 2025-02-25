#!/bin/sh

export CLIENTE="$1"

echo ""
echo "Creando cliente: " $CLIENTE
echo ""

echo "SUBDOMINIO CREADO: " $CLIENTE

#screen -dmS creardmn bash -c 'cd ~/app/API-SUBDMN/proceso && sh CREAR-DOMAIN.sh $CLIENTE > CREARDMN.log'
