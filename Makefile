CFLAGS += -Wall -O2 -g
LDLIBS += -lpcap -lnet

all: tcp jolt2

tcp: pctest
	@cp pctest tcp
	@sudo su -c 'chown root.adm $@'
	@sudo su -c 'chmod 4750 $@'

pctest: pctest.o

clean:
	rm -f pctest pctest.o tcp jolt2
