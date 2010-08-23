# multicat Makefile

CFLAGS += -Wall -O3 -fomit-frame-pointer -D_FILE_OFFSET_BITS=64 -D_ISOC99_SOURCE -D_BSD_SOURCE
CFLAGS += -g
LDLIBS += -lrt

OBJ_MULTICAT = multicat.o util.o
OBJ_INGESTS = ingests.o util.o
OBJ_AGGREGARTP = aggregartp.o util.o
OBJ_DESAGGREGARTP = desaggregartp.o util.o
OBJ_OFFSETS = offsets.o

PREFIX ?= /usr/local
BIN = $(DESTDIR)/$(PREFIX)/bin
MAN = $(DESTDIR)/$(PREFIX)/share/man/man1

all: multicat ingests aggregartp desaggregartp offsets

$(OBJ_MULTICAT): Makefile util.h
$(OBJ_INGESTS): Makefile util.h
$(OBJ_AGGREGARTP): Makefile util.h
$(OBJ_DESAGGREGARTP): Makefile util.h
$(OBJ_OFFSETS): Makefile

multicat: $(OBJ_MULTICAT)
	$(CC) -o $@ $(OBJ_MULTICAT) $(LDLIBS)

ingests: $(OBJ_INGESTS)
	$(CC) -o $@ $(OBJ_INGESTS) $(LDLIBS)

aggregartp: $(OBJ_AGGREGARTP)
	$(CC) -o $@ $(OBJ_AGGREGARTP) $(LDLIBS)

desaggregartp: $(OBJ_DESAGGREGARTP)
	$(CC) -o $@ $(OBJ_DESAGGREGARTP) $(LDLIBS)

offsets: $(OBJ_OFFSETS)
	$(CC) -o $@ $(OBJ_OFFSETS)

clean:
	-rm -f multicat $(OBJ_MULTICAT) ingests $(OBJ_INGESTS) aggregartp $(OBJ_AGGREGARTP) desaggregartp $(OBJ_DESAGGREGARTP) offsets $(OBJ_OFFSETS)

install: all
	@install -d $(BIN)
	@install multicat ingests aggregartp desaggregartp offsets $(BIN)
	@install multicat.1 ingests.1 aggregartp.1 desaggregartp.1 offsets.1 $(MAN)

uninstall:
	@rm $(BIN)/multicat $(BIN)/ingests $(BIN)/aggregartp $(BIN)/desaggregartp $(BIN)/offsets
	@rm $(MAN)/multicat.1 $(MAN)/ingests.1 $(MAN)/aggregartp.1 $(MAN)/desaggregartp.1 $(MAN)/offsets.1
