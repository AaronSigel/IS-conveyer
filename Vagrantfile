require "fileutils"

Vagrant.configure("2") do |config|
  config.vm.box = "cloud-image/ubuntu-24.04"
  config.ssh.insert_key = false

  machines = {
    "wazuh" => {
      ip: "192.168.56.10",
      memory: 10240,
      cpus: 4,
      extra_disk_mb: 20480
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
        vb.customize ["modifyvm", :id, "--ioapic", "on"]
        vb.memory = settings[:memory]
        vb.cpus = settings[:cpus]

        if settings[:extra_disk_mb]
          disks_dir = File.join(__dir__, ".vagrant", "disks")
          FileUtils.mkdir_p(disks_dir)
          extra_disk_path = File.join(disks_dir, "#{name}-data.vdi")

          unless File.exist?(extra_disk_path)
            vb.customize ["createhd", "--filename", extra_disk_path, "--size", settings[:extra_disk_mb]]
          end

          vb.customize [
            "storageattach", :id,
            "--storagectl", "VirtIO Controller",
            "--port", 1,
            "--device", 0,
            "--type", "hdd",
            "--medium", extra_disk_path
          ]
        end
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
