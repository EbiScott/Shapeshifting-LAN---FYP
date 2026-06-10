# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/focal64"  # Ubuntu 20.04 LTS
  config.vm.hostname = "shapeshifting-lan"

  # Network - host-only so attacker can reach the VM
  config.vm.network "private_network", ip: "192.168.56.10"

  # VM resources
  config.vm.provider "virtualbox" do |vb|
    vb.name   = "Shapeshifting LAN Defence"
    vb.memory = "2048"
    vb.cpus   = 2
  end

  # Provisioning script - runs once on first vagrant up
  config.vm.provision "shell", inline: <<-SHELL

    echo "========================================"
    echo " Shapeshifting LAN Defence - Setup"
    echo "========================================"

    # Fix apt sources
    sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
    apt-get update -y

    # Install dependencies
    apt-get install -y git python3-pip tmux net-tools

    # Install Mininet
    apt-get install -y mininet

    # Install Open vSwitch
    apt-get install -y openvswitch-switch
    service openvswitch-switch start

    # Install Ryu from source
    cd /home/vagrant
    git clone https://github.com/faucetsdn/ryu.git
    cd ryu
    pip3 install .
    echo 'export PATH=$PATH:/home/vagrant/.local/bin' >> /home/vagrant/.bashrc

    # Clone the project
    cd /home/vagrant
    git clone https://github.com/EbiScott/Shapeshifting-LAN---FYP.git project
    chown -R vagrant:vagrant /home/vagrant/project

    # Install scapy for testing
    pip3 install scapy

    echo "========================================"
    echo " Setup complete!"
    echo " Run: cd project && ryu-manager shapeshifting_controller_V2.py"
    echo "========================================"

  SHELL
end
