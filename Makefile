LDLIBS += -lnet -lpcap -lpthread

TARGET = pctest

all: $(TARGET)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	./tcp

ifneq "$(PICKY)" "0"
NITPICKY_WARNINGS =	\
			-W \
			-Waggregate-return \
			-Wall \
			-Wbad-function-cast \
			-Wcast-align \
			-Wcast-qual \
			-Wchar-subscripts \
			-Wcomment \
			-Wdisabled-optimization \
			-Wendif-labels \
			-Werror \
			-Wfloat-equal \
			-Wformat=2 \
			-Wimplicit \
			-Winline \
			-Wmain \
			-Wmissing-braces \
			-Wmissing-declarations \
			-Wmissing-format-attribute \
			-Wmissing-noreturn \
			-Wmissing-prototypes \
			-Wnested-externs \
			-Wnonnull \
			-Wpadded \
			-Wparentheses \
			-Wpointer-arith \
			-Wredundant-decls \
			-Wreturn-type \
			-Wsequence-point \
			-Wshadow \
			-Wsign-compare \
			-Wstrict-aliasing \
			-Wstrict-prototypes \
			-Wswitch \
			-Wswitch-enum \
			-Wtrigraphs \
			-Wundef
ifeq "$(DEBUG)" ""
NITPICKY_WARNINGS +=	-Wuninitialized
endif
NITPICKY_WARNINGS +=	\
			-Wunknown-pragmas \
			-Wunused \
			-Wwrite-strings \
			-pedantic \
			-std=c99 \

CFLAGS += $(NITPICKY_WARNINGS)
endif

ifneq "$(DEBUG)" ""
CFLAGS += -g3 -O0
else
CFLAGS += -O3
endif
