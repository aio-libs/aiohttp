#!/bin/bash

rm -rf $PWD/reports
mkdir $PWD/reports

USER_ID=$(id -u) docker-compose -p aiohttp-autobahn -f $PWD/images-for-compose.yml build --parallel

docker-compose -f $PWD/client/docker-compose.yml up --abort-on-container-exit
docker-compose -f $PWD/client/docker-compose.yml down
