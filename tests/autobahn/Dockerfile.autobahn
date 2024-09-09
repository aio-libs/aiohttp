FROM crossbario/autobahn-testsuite:0.8.2

RUN apt-get update && apt-get install python3 python3-pip -y
RUN pip3 install wait-for-it

CMD ["wstest", "--mode", "fuzzingserver", "--spec", "/config/fuzzingserver.json"]
