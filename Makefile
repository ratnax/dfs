CFLAGS=-Wfatal-errors -ggdb2 -O3
LDFLAGS=-lpthread

EXT=bt_ext.h pm_ext.h bm_ext.h
PM_INT=pm_int.h
BM_INT=bm_int.h
BT_INT=bt_int.h

PM_EXT=pm_ext.h
BM_EXT=bm_ext.h
BT_EXt=bt_ext.h

GLOBAL=global.h find_bit.c

TARGETS=bm_mkfs bm_test bt_test
all: $(TARGETS)
pm.o: pm.c $(PM_INT) $(PM_EXT) $(GLOBAL)
	gcc -c pm.c $(CFLAGS) -o $@
bm.o: bm.c $(BM_INT) $(BM_EXT) $(PM_EXT) $(GLOBAL)
	gcc -c bm.c $(CFLAGS) -o $@
bt.o: bt.c $(BT_INT) $(BT_EXT) $(PM_EXT) $(BM_EXT) $(GLOBAL)
	gcc -c bt.c $(CFLAGS) -o $@
bm_page.o: bm_page.c $(BM_INT) $(BM_EXT) $(PM_EXT) $(GLOBAL)
	gcc -c bm_page.c $(CFLAGS) -o $@
bt_page.o: bt_page.c $(BT_INT) $(BT_EXT) $(BM_EXT) $(PM_EXT) $(GLOBAL)
	gcc -c bt_page.c $(CFLAGS) -o $@
bm_main.o: bm.c $(BM_INT) $(BM_EXT) $(PM_EXT) $(GLOBAL)
	gcc -c bm.c -DTEST $(CFLAGS) -o $@
bt_main.o: bt.c $(BT_INT) $(BT_EXT) $(BM_EXT) $(PM_EXT) $(GLOBAL)
	gcc -c bt.c -DTEST $(CFLAGS) -o $@
bm_mkfs.o: bm.c $(BM_INT) $(BM_EXT) $(PM_EXT) $(GLOBAL)
	gcc -c bm.c -DMKFS $(CFLAGS) -o $@
bm_test: bm_main.o bm_page.o pm.o
	gcc -o $@ bm_main.o bm_page.o pm.o $(CFLAGS) $(LDFLAGS)
bm_mkfs: bm_mkfs.o bm_page.o pm.o  
	gcc -o $@ bm_mkfs.o bm_page.o pm.o $(CFLAGS) $(LDFLAGS)
bt_test: bt_main.o bt_page.o bm.o bm_page.o pm.o  
	gcc -o $@ bt_main.o bt_page.o bm.o bm_page.o pm.o $(CFLAGS) $(LDFLAGS)
clean: 
	rm -f *.o $(TARGETS)
