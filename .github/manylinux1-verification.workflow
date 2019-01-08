workflow "manylinux1 verification workflow" {
  on = "push"
  resolves = ["manylinux1"]
}

action "manylinux1" {
  uses = "actions/docker/cli@76ff57a6c3d817840574a98950b0c7bc4e8a13a8"
  args = "./tools/run_docker.sh \"aiohttp\""
  runs = "/bin/sh"
}
