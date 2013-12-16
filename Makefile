CC	= gcc
DEFS    = -Wl,-rpath=/home/work/local/libphenom/lib `pkg-config libphenom --cflags --libs` -L/home/work/local/libphenom/lib
CFLAGS	= -g -Wall
INCDIR  = -I./include -I/home/work/local/libphenom/include
OBJ     = fcgi.o fcgi_header.o
LIBS    = -lphenom -lssl

fcgi: $(OBJ)
	$(CC) $(CFLAGS) $(DEFS) $(LDFLAGS) -o $@ $(OBJ)  $(LIBS)

clean:
	rm -rf *.o
	rm fcgi
.c.o:
	$(CC) -c $(CFLAGS) $(DEFS) $(INCDIR) $< 

