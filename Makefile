CFLAGS=-Wfatal-errors -O3
LDFLAGS="-lpthread"

t: t_mem.o mp_mem.o
	gcc -o t t_mem.o mp_mem.o $(CFLAGS) $(LDFLAGS)

t_mem.o: t_mem.c mp_mem.h
	gcc -c t_mem.c $(CFLAGS)

mp_mem.o: mp_mem.c mp_mem.h
	gcc -c mp_mem.c $(CFLAGS)

clean: 
	rm -rf *.o
