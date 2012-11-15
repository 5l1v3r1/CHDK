topdir=../../

include $(topdir)makefile.inc

CFLAGS += -D__CHDK__ -DLITTLE_ENDIAN

OBJS = eyefi.o eyefi-chdk.o md5.o sha1.o

all: libeyefi.a

libeyefi.a: $(OBJS)

clean:
	rm -f $(OBJS) libeyefi.a

distclean: clean
	rm -f $(OBJS:.o=.d)

include $(topdir)bottom.inc
