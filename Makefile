CFLAGS += -Wall -O2 -g
LDLIBS += -lpcap -lnet -lpthread

TARGET = pctest

all: $(TARGET)

clean:
	rm -f $(TARGET)
