workflow "manylinux1 verification workflow" {
  on = "push"
  resolves = [
    "re-actors/manylinux1_x86_64-action@master",
  ]
}

action "re-actors/manylinux1_x86_64-action@master" {
  uses = "re-actors/manylinux1_x86_64-action@master"
  env = {
    PYPI_PKG_DIST_NAME = "aiohttp"
    BUILD_SCRIPT_PATH = "tools/build-wheels.sh"
  }
}
