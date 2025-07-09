#!/bin/bash

docker compose down
docker compose up styxdb -d
while :; do
    docker compose logs | grep 'database system is ready to accept connections' && break
    echo "Waiting for database..."
    sleep 1
done
echo
echo "Database up, create styxdb"
node=$(docker compose ps styxdb | grep styxdb|awk '{print $1}')
docker exec -it "${node}"  psql -c 'create database styxdb'
docker compose down
