FROM python:3.11-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3 AS builder

ENV AIOHTTP_NO_EXTENSIONS=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src
COPY . .
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.11-slim-bookworm@sha256:d29f48a31a8b408ed19272ca1e7b10ebae13b240a27e862d3d4217c528e2e0c3

ENV AIOHTTP_NO_EXTENSIONS=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index \
        --find-links=/wheels /wheels/aiohttp-*.whl \
    && rm -rf /wheels \
    && groupadd --system aiohttp \
    && useradd --system --gid aiohttp --no-create-home aiohttp

USER aiohttp
WORKDIR /app

CMD ["python", "-c", "import aiohttp; print(f'aiohttp {aiohttp.__version__} import OK')"]