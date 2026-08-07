# =============================================================================
# original-reconstructed.Dockerfile
#
# Reverse-engineered from docker-build-failed.logs.
# Target image : sweb.eval.x86_64.aio-libs__aiohttp-11290:latest
# Repository   : aio-libs/aiohttp @ PR #11290  (4.0.0a2.dev0, HEAD 9b0153c14)
#
# THIS IS THE BROKEN BUILD - it is meant to fail, and it reproduces the
# recorded failure exactly:
#
#   + pip install --no-cache-dir -e .
#   Obtaining file:///testbed
#   Getting requirements to build editable: finished with status 'error'
#   x Getting requirements to build editable did not run successfully.
#   | exit code: 2
#   +-> Install submodules when building from git clone
#       Hint:
#         git submodule update --init
#
# Every instruction below is annotated with the log line that justifies it.
# =============================================================================

# Log: apt sources are all "jammy" (22.04); packages resolved as "amd64".
FROM ubuntu:22.04

# Log: "+ export DEBIAN_FRONTEND=noninteractive"
ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# Environment supplied by the SWE-bench base layer (sweb.base.py.x86_64).
# Log: "Current environment: testbed"
# Log: "/opt/miniconda3/envs/testbed/lib/python3.11/site-packages"
# Log: "++ export CONDA_PREFIX=/opt/miniconda3/envs/testbed"
# Reconstructed explicitly here so this Dockerfile stands alone.
# ---------------------------------------------------------------------------
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget bzip2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# NOTE: the SWE-bench base layer ships Miniconda. Miniforge is substituted here
# because repo.anaconda.com now refuses non-interactive installs until its
# Terms of Service are accepted (CondaToSNonInteractiveError). Miniforge is the
# same conda, defaulting to conda-forge, and keeps the /opt/miniconda3 layout
# and the "testbed" env name identical to the log.
RUN wget -qO /tmp/miniforge.sh \
        "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-$(uname -m).sh" \
    && bash /tmp/miniforge.sh -b -p /opt/miniconda3 \
    && rm -f /tmp/miniforge.sh

ENV PATH=/opt/miniconda3/bin:$PATH
RUN conda create -y -n testbed python=3.11 && conda clean -afy
ENV PATH=/opt/miniconda3/envs/testbed/bin:/opt/miniconda3/condabin:$PATH \
    CONDA_DEFAULT_ENV=testbed \
    CONDA_PREFIX=/opt/miniconda3/envs/testbed

# Log: "Obtaining file:///testbed"  ->  the checkout lives at /testbed
WORKDIR /testbed
COPY . /testbed

# ---------------------------------------------------------------------------
# pre_install block, reproduced in the EXACT order recorded by `set -x`
# in /root/setup_repo.sh.
# ---------------------------------------------------------------------------

# Log: "+ apt-get update"
# Log: "+ apt-get install -y build-essential gcc git libffi-dev libssl-dev python3-dev"
RUN apt-get update \
    && apt-get install -y build-essential gcc git libffi-dev libssl-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Log: "+ pip install --upgrade pip setuptools wheel Cython"
RUN pip install --upgrade pip setuptools wheel Cython

# Log: "+ pip install --no-cache-dir attrs charset-normalizer multidict yarl
#       async-timeout frozenlist aiosignal pytest pytest-asyncio pytest-aiohttp trustme"
RUN pip install --no-cache-dir attrs charset-normalizer multidict yarl \
        async-timeout frozenlist aiosignal pytest pytest-asyncio pytest-aiohttp trustme

# Log: "+ pip install --no-cache-dir -e ."
# >>>>>>>>>>>>>>>>>>>>>>>> THE BUILD DIES ON THIS LINE <<<<<<<<<<<<<<<<<<<<<<<<
# setup.py aborts with exit code 2 because vendor/llhttp/README.md is absent:
# the submodule has not been initialised yet.
RUN pip install --no-cache-dir -e .

# Log: this command IS in the spec, but it is ordered AFTER the install that
# depends on it, so `set -e` in setup_repo.sh means it is never reached.
# THIS ORDERING IS THE BUG.
RUN git submodule update --init --recursive

# Log: "test_cmd": "python -m pytest -v -rA tests/test_client_functional.py tests/test_payload.py"
CMD ["python", "-m", "pytest", "-v", "-rA", \
     "tests/test_client_functional.py", "tests/test_payload.py"]
