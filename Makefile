CFLAGS += -Wall -O2 -g
LDLIBS += -lpcap -lnet -lpthread

TARGET = pctest
OBJS = list.o pctest.o
SRCS = Makefile *.c *.h

all: $(TARGET)

$(TARGET): $(OBJS)

$(OBJS): list.h

clean:
	rm -f $(TARGET) $(OBJS) $(TARGET).tgz

dist:
	rm -f $(TARGET).tgz
	mkdir -p tmp/$(TARGET)
	cp $(SRCS) tmp/$(TARGET)
	cd tmp && tar zcf ../$(TARGET).tgz $(TARGET)
	rm -rf tmp
