Vagrant.configure("2") do |config|
  config.vm.box = "generic/centos8"
  config.vm.provision "shell", :path => "misc/provision.sh", :privileged => false
end
