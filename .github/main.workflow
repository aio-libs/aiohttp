workflow "manylinux1 verification workflow" {
  on = "push"
  resolves = [
    "re-actors/manylinux1_x86_64-action@master",
  ]
}

action "actions-experiment-filter-webknjaz" {
  uses = "actions/bin/filter@master"
  args = "branch *webknjaz*"
}

action "re-actors/manylinux1_x86_64-action@master" {
  needs = "actions-experiment-filter-webknjaz"
  uses = "re-actors/manylinux1_x86_64-action@cb811ef"
  env = {
    PYPI_PKG_DIST_NAME = "aiohttp"
    BUILD_SCRIPT_PATH = "tools/build-wheels.sh"
  }
}
