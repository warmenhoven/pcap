CFLAGS += -Wall -O2 -g
LDLIBS += -lpcap -lnet -lpthread

all: tcp jolt2

tcp: pctest
	@sudo su -c 'cp $< $@'
	@sudo su -c 'chown root.adm $@'
	@sudo su -c 'chmod 4750 $@'

pctest: list.o pctest.o

list.o pctest.o: list.h

clean:
	rm -f pctest pctest.o tcp jolt2
