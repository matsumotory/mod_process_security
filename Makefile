##
##  Makefile -- Build procedure for sample mod_process_security Apache module
##	  MATSUMOTO, Ryosuke
##

# target module source
TARGET=mod_process_security.c

#   the used tools
APXS=apxs
APACHECTL=apachectl
#APXS=/usr/local/apache2.4/bin/apxs
#APACHECTL=/usr/local/apache2.4/bin/apachectl

#   additional user defines, includes and libraries
#DEF=-DSYSLOG_NAMES
INC=
LIB=-lcap
WC=-Wc,-std=c99

#   the default target
all: mod_process_security.so

#   compile the DSO file
mod_process_security.so: $(TARGET)
	$(APXS) -c $(DEF) $(INC) $(LIB) $(WC) $(TARGET)

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	$(APXS) -i -a -n 'process_security' .libs/mod_process_security.so

#   cleanup
clean:
	-rm -rf .libs *.o *.so *.lo *.la *.slo *.loT

start:
	$(APACHECTL) -k start
restart:
	$(APACHECTL) -k restart
stop:
	$(APACHECTL) -k stop

test:
	curl -s http://127.0.0.1:8080/cgi-bin/id.cgi | grep -q "500:500:500"

.PHONY: test

