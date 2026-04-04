Vagrant.configure("2") do |config|
  config.vm.box = "cloud-image/ubuntu-24.04"
  config.ssh.insert_key = false

  machines = {
    "wazuh" => {
      ip: "192.168.56.10",
      memory: 4096,
      cpus: 2
    },
    "target1" => {
      ip: "192.168.56.11",
      memory: 2048,
      cpus: 2
    },
    "target2" => {
      ip: "192.168.56.12",
      memory: 2048,
      cpus: 2
    }
  }

  machines.each do |name, settings|
    config.vm.define name do |machine|
      machine.vm.hostname = name
      machine.vm.network "private_network", ip: settings[:ip]

      machine.vm.provider "virtualbox" do |vb|
        vb.name = "ib-host-audit-poc-#{name}"
        vb.memory = settings[:memory]
        vb.cpus = settings[:cpus]
      end

      # Placeholder provisioner: keeps `vagrant up` stable until host-side Ansible runs.
      machine.vm.provision "shell", inline: <<-SHELL
        set -eu
        mkdir -p /opt/ib-host-audit-poc
        echo "#{name}" > /opt/ib-host-audit-poc/node-name
      SHELL
    end
  end
end
