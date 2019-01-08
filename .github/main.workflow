workflow "manylinux1 verification workflow" {
  on = "push"
  resolves = ["manylinux1"]
}

action "manylinux1" {
  uses = "re-actors/docker/cli@docker-cli-bash"
  args = "./tools/run_docker.sh \"aiohttp\""
  runs = "/bin/bash"
}
