#/bin/bash

sudo dnf -y update && \
sudo dnf -y install gcc make httpd httpd-devel pkgconfig libcap-devel redhat-rpm-config gdb && \
sudo dnf clean all && \
sudo rm -rf /var/cache/dnf

curl -o v1.1.4.tar.gz -LO https://github.com/matsumotory/mod_process_security/archive/v1.1.4.tar.gz && \
tar zxf v1.1.4.tar.gz && \
cd mod_process_security-1.1.4 && \
make && \
sudo make install && \
cd .. && \
sudo rm -rf v1.1.4.tar.gz mod_process_security-1.1.4 

sudo echo "LoadModule mpm_prefork_module modules/mod_mpm_prefork.so" | sudo tee /etc/httpd/conf.modules.d/00-mpm.conf && \
sudo echo -e 'ErrorLog /dev/stderr\n
TransferLog /dev/stdout\n
<Directory /var/www/html>\n
    Options Indexes ExecCGI\n
</Directory>\n
AddHandler cgi-script .cgi .pl\n
PSExAll On' | sudo tee /etc/httpd/conf.d/mod_process_security.conf

sudo groupadd -g 10000 user1 && \
sudo useradd -u 10000 -g user1 user1 && \
sudo echo '<a href="test.pl">test.pl</a>' | sudo tee /var/www/html/index.html && \
sudo echo -e '#!/bin/env perl\n
use strict;\n
print "Content-type: text/html; charset=UTF-8\\n\\n";\n
my $real_uid = $<;\n
my $real_name = getpwuid($real_uid);\n
my $effective_uid = $>;\n
my $effective_name = getpwuid($effective_uid);\n
print "real_uid : $real_uid ($real_name)<br />";\n
print "effective_uid : $effective_uid ($effective_name)<br /><br />";\n
exit;' | sudo tee /var/www/html/test.pl && \
sudo chmod 755 /var/www/html/test.pl && \
sudo chown -R user1: /var/www/html


# /usr/sbin/httpd -D FOREGROUND

