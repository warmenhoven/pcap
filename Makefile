CFLAGS += -Wall -O2 -g
LDLIBS += -lpcap -lnet

pcroot: pctest
	@sudo su -c 'chown root.adm $<'
	@sudo su -c 'chmod 4750 $<'

pctest: pctest.o

clean:
	rm -f pctest pctest.o
