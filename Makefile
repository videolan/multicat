# multicat Makefile

VERSION = 2.3
CFLAGS += -Wall -Wformat-security -O3 -fomit-frame-pointer -D_FILE_OFFSET_BITS=64 -D_ISOC99_SOURCE -D_BSD_SOURCE -D_DEFAULT_SOURCE
CFLAGS += -g

ifneq ($(shell uname -s),Darwin)
	LDLIBS += -lrt -pthread
endif

OBJ_MULTICAT = multicat.o util.o
OBJ_INGESTS = ingests.o util.o
OBJ_AGGREGARTP = aggregartp.o util.o
OBJ_REORDERTP = reordertp.o util.o
OBJ_OFFSETS = offsets.o util.o
OBJ_LASTS = lasts.o
OBJ_MULTICAT_VALIDATE = multicat_validate.o util.o
OBJ_MULTILIVE = multilive.o util.o

PREFIX ?= /usr/local
BIN = $(DESTDIR)/$(PREFIX)/bin
MAN = $(DESTDIR)/$(PREFIX)/share/man/man1

all: multicat ingests aggregartp reordertp offsets lasts multicat_validate multilive

$(OBJ_MULTICAT): Makefile util.h
$(OBJ_INGESTS): Makefile util.h
$(OBJ_AGGREGARTP): Makefile util.h
$(OBJ_REORDERTP): Makefile util.h
$(OBJ_OFFSETS): Makefile util.h
$(OBJ_LASTS): Makefile
$(OBJ_MULTICAT_VALIDATE): Makefile util.h
$(OBJ_MULTILIVE): Makefile util.h

multicat: $(OBJ_MULTICAT)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_MULTICAT) $(LDLIBS)

ingests: $(OBJ_INGESTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_INGESTS) $(LDLIBS)

aggregartp: $(OBJ_AGGREGARTP)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_AGGREGARTP) $(LDLIBS)

reordertp: $(OBJ_REORDERTP)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_REORDERTP) $(LDLIBS)

offsets: $(OBJ_OFFSETS)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_OFFSETS) $(LDLIBS)

lasts: $(OBJ_LASTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_LASTS) $(LDLIBS)

multicat_validate: $(OBJ_MULTICAT_VALIDATE)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_MULTICAT_VALIDATE) $(LDLIBS)

multilive: $(OBJ_MULTILIVE)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_MULTILIVE) $(LDLIBS)

clean:
	-rm -f multicat $(OBJ_MULTICAT) ingests $(OBJ_INGESTS) aggregartp $(OBJ_AGGREGARTP) reordertp $(OBJ_REORDERTP) offsets $(OBJ_OFFSETS) lasts $(OBJ_LASTS) multicat_validate $(OBJ_MULTICAT_VALIDATE) multilive $(OBJ_MULTILIVE)

install: all
	@install -d $(BIN)
	@install -d $(MAN)
	@install multicat ingests aggregartp reordertp offsets lasts multicat_validate multilive $(BIN)
	@install multicat.1 ingests.1 aggregartp.1 reordertp.1 offsets.1 lasts.1 $(MAN)

uninstall:
	@rm $(BIN)/multicat $(BIN)/ingests $(BIN)/aggregartp $(BIN)/reordertp $(BIN)/offsets $(BIN)/lasts $(BIN)/multicat_validate $(BIN)/multilive
	@rm $(MAN)/multicat.1 $(MAN)/ingests.1 $(MAN)/aggregartp.1 $(MAN)/reordertp.1 $(MAN)/offsets.1 $(MAN)/lasts.1

dist:
	git archive --format=tar --prefix=multicat-$(VERSION)/ master | bzip2 -9 > multicat-$(VERSION).tar.bz2
	ls -l multicat-$(VERSION).tar.bz2

