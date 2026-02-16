# PathOps Demo Bootstrap

## Multi-tenancy (demo only)

This demo uses virtual clusters (vcluster) to simulate
per-user Kubernetes clusters.

Each user gets:
- one vcluster
- three namespaces: agents, preflight, production

In the real PathOps product, users bring their own clusters.

## Requirements
- VirtualBox
- Vagrant
- Ansible

## Quick Start

cd vagrant
vagrant up

cd ../ansible
ansible-playbook -i inventories/demo/hosts.ini playbooks/site.yml

## Architecture
<!-- TODO: diagram -->

(diagrama simple)
