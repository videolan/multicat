# multicat Makefile

CFLAGS += -Wall -O3 -fomit-frame-pointer -D_FILE_OFFSET_BITS=64 -D_ISOC99_SOURCE -D_BSD_SOURCE
CFLAGS += -g
LDLIBS += -lrt

OBJ_MULTICAT = multicat.o util.o
OBJ_INGESTS = ingests.o util.o
OBJ_AGGREGARTP = aggregartp.o util.o
OBJ_REORDERTP = reordertp.o util.o
OBJ_OFFSETS = offsets.o util.o
OBJ_LASTS = lasts.o

PREFIX ?= /usr/local
BIN = $(DESTDIR)/$(PREFIX)/bin
MAN = $(DESTDIR)/$(PREFIX)/share/man/man1

all: multicat ingests aggregartp reordertp offsets lasts

$(OBJ_MULTICAT): Makefile util.h
$(OBJ_INGESTS): Makefile util.h
$(OBJ_AGGREGARTP): Makefile util.h
$(OBJ_REORDERTP): Makefile util.h
$(OBJ_OFFSETS): Makefile util.h
$(OBJ_LASTS): Makefile

multicat: $(OBJ_MULTICAT)
	$(CC) -o $@ $(OBJ_MULTICAT) $(LDLIBS)

ingests: $(OBJ_INGESTS)
	$(CC) -o $@ $(OBJ_INGESTS) $(LDLIBS)

aggregartp: $(OBJ_AGGREGARTP)
	$(CC) -o $@ $(OBJ_AGGREGARTP) $(LDLIBS)

reordertp: $(OBJ_REORDERTP)
	$(CC) -o $@ $(OBJ_REORDERTP) $(LDLIBS)

offsets: $(OBJ_OFFSETS)
	$(CC) -o $@ $(OBJ_OFFSETS) $(LDLIBS)

lasts: $(OBJ_LASTS)
	$(CC) -o $@ $(OBJ_LASTS) $(LDLIBS)

clean:
	-rm -f multicat $(OBJ_MULTICAT) ingests $(OBJ_INGESTS) aggregartp $(OBJ_AGGREGARTP) reordertp $(OBJ_REORDERTP) offsets $(OBJ_OFFSETS) lasts $(OBJ_LASTS)

install: all
	@install -d $(BIN)
	@install -d $(MAN)
	@install multicat ingests aggregartp reordertp offsets lasts $(BIN)
	@install multicat.1 ingests.1 aggregartp.1 reordertp.1 offsets.1 lasts.1 $(MAN)

uninstall:
	@rm $(BIN)/multicat $(BIN)/ingests $(BIN)/aggregartp $(BIN)/reordertp $(BIN)/offsets $(BIN)/lasts
	@rm $(MAN)/multicat.1 $(MAN)/ingests.1 $(MAN)/aggregartp.1 $(MAN)/reordertp.1 $(MAN)/offsets.1 $(MAN)/lasts.1
