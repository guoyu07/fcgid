CC	= gcc
DEFS    = -Wl,-rpath=/home/work/local/libphenom/lib `pkg-config libphenom --cflags --libs` -L/home/work/local/libphenom/lib
CFLAGS	= -g -Wall
INCDIR  = -I./include
OBJ     = fcgi.o fcgi_header.o

bin/fcgi: $(OBJ)
	$(CC) $(CFLAGS) -O2 $(INCDIR) $(DEFS) $(LDFLAGS) -o $@ $(OBJ)  $(LIBS)

clean:
	rm -rf *.o
	rm bin/fcgi
.c.o:
	$(CC) -c $(CFLAGS) $(DEFS) $(INCDIR) $<


