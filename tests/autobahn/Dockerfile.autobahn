FROM crossbario/autobahn-testsuite:0.8.0

ENV DEBIAN_FRONTEND=noninteractive
RUN \
    apt-get update && \
    apt-get -y install --no-install-recommends bash && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN \
    wget -q https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh -o /usr/bin/wait-for-it && \
    chmod +x /usr/bin/wait-for-it

ARG USER_ID
USER $USER_ID
