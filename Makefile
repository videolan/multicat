# multicat Makefile

CFLAGS += -Wall -O3 -fomit-frame-pointer -D_FILE_OFFSET_BITS=64 -D_ISOC99_SOURCE -D_BSD_SOURCE
CFLAGS += -g
LDFLAGS += -lrt

OBJ_MULTICAT = multicat.o util.o
OBJ_INGESTS = ingests.o util.o
OBJ_AGGREGARTP = aggregartp.o util.o
OBJ_DESAGGREGARTP = desaggregartp.o util.o
OBJ_OFFSETS = offsets.o

BIN = $(DESTDIR)/usr/bin

all: multicat ingests aggregartp desaggregartp offsets

$(OBJ_MULTICAT): Makefile util.h
$(OBJ_INGESTS): Makefile util.h
$(OBJ_AGGREGARTP): Makefile util.h
$(OBJ_DESAGGREGARTP): Makefile util.h
$(OBJ_OFFSETS): Makefile

multicat: $(OBJ_MULTICAT)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_MULTICAT)

ingests: $(OBJ_INGESTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_INGESTS)

aggregartp: $(OBJ_AGGREGARTP)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_AGGREGARTP)

desaggregartp: $(OBJ_DESAGGREGARTP)
	$(CC) $(LDFLAGS) -o $@ $(OBJ_DESAGGREGARTP)

offsets: $(OBJ_OFFSETS)
	$(CC) -o $@ $(OBJ_OFFSETS)

clean:
	-rm -f multicat $(OBJ_MULTICAT) ingests $(OBJ_INGESTS) aggregartp $(OBJ_AGGREGARTP) desaggregartp $(OBJ_DESAGGREGARTP) offsets $(OBJ_OFFSETS)

install: all
	@install -d $(BIN)
	@install multicat ingests aggregartp desaggregartp offsets $(BIN)

uninstall:
	@rm $(BIN)/multicat $(BIN)/ingests $(BIN)/aggregartp $(BIN)/desaggregartp $(BIN)/offsets
