FROM python:3.9.1

ENV DEBIAN_FRONTEND=noninteractive
RUN \
    apt-get update && \
    apt-get -y install --no-install-recommends wait-for-it && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ADD ./ /src
ENV AIOHTTP_NO_EXTENSIONS=1
WORKDIR /src
RUN python setup.py install
