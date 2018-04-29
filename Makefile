CFLAGS=-Wfatal-errors -ggdb2 #-O3
LDFLAGS=-lpthread

EXT=bt_ext.h pm_ext.h bm_ext.h
PM_INT=pm_int.h
BM_INT=bm_int.h
BT_INT=bt_int.h
LM_INT=lm_int.h
TX_INT=tx_int.h
RM_INT=rm_int.h

PM_EXT=pm_ext.h
BM_EXT=bm_ext.h
BT_EXT=bt_ext.h
LM_EXT=lm_int.h
TX_EXT=tx_ext.h
RM_EXT=rm_ext.h

GLOBAL=global.h find_bit.c list.h ondisk_format.h

TARGETS=mkfs test bm_test

all: $(TARGETS)

pm.o: pm.c $(TX_INT) $(TX_EXT) $(PM_INT) $(PM_EXT) $(GLOBAL)
	gcc -c pm.c $(CFLAGS) -o $@
bm.o: bm.c $(BM_INT) $(BM_EXT) $(PM_EXT) $(TX_EXT) $(GLOBAL)
	gcc -c bm.c $(CFLAGS) -o $@
bt.o: bt.c $(BT_INT) $(BT_EXT) $(PM_EXT) $(BM_EXT) $(TX_EXT) $(GLOBAL)
	gcc -c bt.c $(CFLAGS) -o $@
lm.o: lm.c $(LM_INT) $(LM_EXT) $(PM_EXT) $(BM_EXT) $(GLOBAL)
	gcc -c lm.c $(CFLAGS) -o $@
rm.o: rm.c $(RM_INT) $(LM_EXT) $(TX_INT) $(PM_EXT) $(BM_EXT) $(GLOBAL)
	gcc -c rm.c $(CFLAGS) -o $@
bm_page.o: bm_page.c $(BM_INT) $(BM_EXT) $(PM_EXT) $(TX_EXT) $(GLOBAL)
	gcc -c bm_page.c $(CFLAGS) -o $@
bt_page.o: bt_page.c $(BT_INT) $(BT_EXT) $(BM_EXT) $(PM_EXT) \
		$(TX_EXT) $(GLOBAL)
	gcc -c bt_page.c $(CFLAGS) -o $@
tx.o: tx.c $(TX_INT) $(TX_EXT) $(GLOBAL)
	gcc -c tx.c $(CFLAGS) -o $@

bm_main.o: bm.c $(BM_INT) $(BM_EXT) $(PM_EXT) $(TX_EXT) $(GLOBAL)
	gcc -c bm.c -DTEST $(CFLAGS) -o $@
bm_test: bm_main.o bm_page.o pm.o tx.o lm.o rm.o
	gcc -o $@ bm_main.o bm_page.o pm.o tx.o lm.o rm.o \
	$(CFLAGS) $(LDFLAGS)

test.o: test.c $(BT_EXT) $(BM_EXT) $(PM_EXT) $(LM_EXT) $(TX_EXT) $(GLOBAL)
	gcc -c test.c $(CFLAGS) -o $@
test: test.o bt.o bt_page.o bm.o bm_page.o pm.o tx.o lm.o rm.o
	gcc -o $@ test.o bt.o bt_page.o bm.o bm_page.o pm.o tx.o lm.o \
	rm.o $(CFLAGS) $(LDFLAGS)

mkfs.o: mkfs.c $(BT_EXT) $(BM_EXT) $(PM_EXT) $(LM_EXT) $(TX_EXT) $(GLOBAL)
	gcc -c mkfs.c $(CFLAGS) -o $@
mkfs: mkfs.o bt.o bt_page.o bm.o bm_page.o pm.o tx.o lm.o rm.o
	gcc -o $@ mkfs.o bt.o bt_page.o bm.o bm_page.o pm.o tx.o lm.o \
	rm.o $(CFLAGS) $(LDFLAGS)
clean: 
	rm -f *.o $(TARGETS)
