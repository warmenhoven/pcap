CFLAGS += -Wall -O2 -g -ansi -pedantic
LDLIBS += -lpcap -lnet -lpthread

TARGET = pctest

all: $(TARGET)

clean:
	rm -f $(TARGET)
