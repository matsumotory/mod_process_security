#/bin/bash

sudo dnf -y update && \
sudo dnf -y install gcc make httpd httpd-devel pkgconfig libcap-devel redhat-rpm-config gdb git && \
sudo dnf clean all && \
sudo rm -rf /var/cache/dnf

git clone https://github.com/matsumotory/mod_process_security.git
cd mod_process_security && \
make && \
sudo make install && \
cd .. && \

sudo echo "LoadModule mpm_prefork_module modules/mod_mpm_prefork.so" | sudo tee /etc/httpd/conf.modules.d/00-mpm.conf && \
sudo echo -e 'ErrorLog /dev/stderr\n
TransferLog /dev/stdout\n
<Directory /var/www/html>\n
    Options Indexes ExecCGI\n
</Directory>\n
AddHandler cgi-script .cgi .pl\n
PSExAll On' | sudo tee /etc/httpd/conf.d/mod_process_security.conf

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
sudo chown -R 55226:55226 /var/www/html


# /usr/sbin/httpd -D FOREGROUND

