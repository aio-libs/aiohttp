#!/bin/bash

rm -rf reports
mkdir reports
docker-compose -f client/docker-compose.yml
