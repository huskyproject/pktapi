.SUFFIXES: .c .obj

DBGOPT=-Ti+ -Ge- -Ms -Si+ -Fi+ -B" /de /nologo"
COPT  =-Ge- -Gm+ -Gi+ -Gf+ -Gs+ -G5 -O+ -Oc- -Op+ -Ms -Si+ -Fi+ -Ss+ -D__NOINTEL__
CC    =icc -q $(COPT) -I..\h;..\..\msgapi\h
O     =obj
DLL   =pktapi32.dll
LIB   =..\lib\pktapi32.lib

all: $(DLL) $(LIB)

OBJS=p2_pkt.$(O) pktapi.$(O) p2_read.$(O) p2_write.$(O) strrstr.$(O) \
     ctrlbuf.$(O) platform.$(O)

SLIB=

XLIB=..\..\msgapi\lib\msgapi32.lib

$(DLL): $(OBJS) $(SLIB)
 $(CC) -Fe"$@" $(OBJS) $(SLIB) $(XLIB) pktapi.def

.c.obj:
	$(CC) -c $<

$(LIB): $(DLL)
	implib $@ $(DLL)
        lxlite $(DLL)
