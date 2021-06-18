#!/bin/bash

rm -rf $PWD/reports
mkdir $PWD/reports

docker-compose -p aiohttp-autobahn build

docker-compose -f $PWD/client/docker-compose.yml up --abort-on-container-exit
docker-compose -f $PWD/client/docker-compose.yml down

docker-compose -f $PWD/server/docker-compose.yml up --abort-on-container-exit
docker-compose -f $PWD/server/docker-compose.yml down
