CFLAGS += -Wall -O2 -g
LDLIBS += -lpcap -lnet -lpthread

TARGET = pctest

all: $(TARGET)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	./tcp

ifneq "$(PICKY)" ""
NITPICKY_WARNINGS = -Werror \
		    -Wall \
		    -Wundef \
		    -Wendif-labels \
		    -Wshadow \
		    -Wpointer-arith \
		    -Wcast-align \
		    -Wsign-compare \
		    -Waggregate-return \
		    -Wstrict-prototypes \
		    -Wmissing-prototypes \
		    -Wmissing-declarations \
		    -Wpadded \
		    -Wredundant-decls \
		    -Wnested-externs \
		    -Winline \
		    -std=c99 \
		    -pedantic

CFLAGS += $(NITPICKY_WARNINGS)
endif

