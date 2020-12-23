#!/bin/bash

rm -rf $PWD/reports
mkdir $PWD/reports
USER_ID=$(id -u) docker-compose -f $PWD/client/docker-compose.yml up --build --abort-on-container-exit
