FROM public.ecr.aws/x8v8d7g8/mars-base:latest

WORKDIR /app
COPY . .

RUN pip install -e .[test] pytest aiohttp
CMD ["/bin/bash"]

