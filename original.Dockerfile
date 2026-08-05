FROM sweb.env.py.x86_64.3bb2f0e92d01ae3d2f2ae7:latest

COPY ./setup_repo.sh /root/
RUN sed -i -e 's/\r$//' /root/setup_repo.sh
RUN /bin/bash /root/setup_repo.sh

WORKDIR /testbed/
