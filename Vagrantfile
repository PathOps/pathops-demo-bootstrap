# Vagrantfile
require "yaml"

CFG_PATH = File.join(__dir__, "vagrant", "config", "vms.yml")
cfg = YAML.load_file(CFG_PATH)

Vagrant.configure("2") do |config|
  config.vm.box = cfg.dig("project", "ubuntu_box") || "bento/ubuntu-24.04"

  cfg["vms"].each do |vm|
    config.vm.define vm["name"] do |node|
      node.vm.hostname = vm["hostname"]

      node.vm.network "private_network",
        ip: vm["ip"],
        virtualbox__intnet: false

      node.vm.provider "virtualbox" do |vb|
        vb.name = vm["name"]
        vb.cpus = vm["cpus"] || 2
        vb.memory = vm["memory"] || 2048
      end

      node.vm.provision "shell", inline: <<-SHELL
        set -euxo pipefail
        sudo apt-get update -y
        sudo apt-get install -y python3 python3-apt ca-certificates curl
        echo "#{vm["hostname"]}" | sudo tee /etc/hostname
      SHELL
    end
  end
end
