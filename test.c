#include "global.h"
#include "bt_ext.h"
#include "lm_ext.h"
#include "bm_ext.h"
#include "tx_ext.h"

BTREE *t;

#define MAX_ELE     (100000)
#define MAX_THREAD  (8)

#define MAX_REGIONS (MAX_ELE / (3 * MAX_THREAD))

char bitmap[MAX_ELE / 8 + 1];

int switcher[][3] = { {0, 1, 2},
                      {0, 2, 1},
                      {1, 0, 2},
                      {1, 2, 0},
                      {2, 0, 1},
                      {2, 1 ,0} };
int si;

static void
shuffle(uint32_t *arr)
{
	int i, j;

	for (i = 0; i < MAX_REGIONS; i++) {
		j = random() % (i + 1);
		arr[i] = arr[j];
		arr[j] = i;
	}
}

static void *
looker(void *arg)
{
	unsigned long id  = (unsigned long) arg;
	int err, i;
	uint32_t key;
	uint32_t kmem[64];
	uint32_t vmem[64];
	uint32_t p[MAX_REGIONS];
	DBT k, v;

	memset(kmem, 0, sizeof(kmem));
	memset(vmem, 0, sizeof(vmem));
	shuffle(p);

	k.data = kmem;
	k.size = 32;
	v.data = vmem;
	v.size = 250;
	for (i = 0; i < MAX_REGIONS; i++) {
		key = p[i] * MAX_THREAD * 3 + id * 3 + switcher[si][0];
		kmem[0] = key;
		vmem[0] = key;
		err = bt_get(t, &k, &v); 
		if (!err) {
			assert(bitmap[key >> 3] & (1 << (key % 8)));
		} else if (err == -ENOENT) {
			assert(!(bitmap[key >> 3] & (1 << (key % 8))));
		} else {
			fprintf(stderr, "error in lookup\n");
		}
	}
	return NULL;
}

static void *
inserter(void *arg)
{
	unsigned long id  = (unsigned long) arg;
	uint32_t key;
	uint32_t kmem[64];
	uint32_t vmem[64];
	uint32_t p[MAX_REGIONS];
	int err, i;
	DBT k, v;
	struct txn *tx;

	memset(kmem, 0, sizeof(kmem));
	memset(vmem, 0, sizeof(vmem));
	shuffle(p);

	k.data = kmem;
	k.size = 32;
	v.data = vmem;
	v.size = 250;
	for (i = 0; i < MAX_REGIONS; i++) {
		key = p[i] * MAX_THREAD * 3 + id * 3 + switcher[si][1];
		kmem[0] = key;
		vmem[0] = key;
		v.size = 250; //key % 249 + 1;

		tx = txn_alloc(false);
		assert(!IS_ERR(tx));

		err = bt_put(tx, t, &k, &v); 
		if (!err) {
			assert(!(bitmap[key >> 3] & (1 << (key % 8))));
			// assert(v.size == key % 249 + 1);
			__sync_fetch_and_or(&bitmap[key >> 3], 1 << (key % 8));
		} else if (err == -EEXIST) {
			assert(bitmap[key >> 3] & (1 << (key % 8)));
		} else {
			fprintf(stderr, "error in insert\n");
		}
		err = txn_commit(tx, false);
		assert(!err);
		// txn_free(tx);
	}
	return NULL;
}

static void *
deleter(void *arg)
{
	unsigned long id  = (unsigned long) arg;
	int err, i;
	uint32_t key;
	uint32_t kmem[64];
	uint32_t p[MAX_REGIONS];
	DBT k;
	struct txn *tx;

	memset(kmem, 0, sizeof(kmem));
	shuffle(p);

	k.data = kmem;
	k.size = 32;
	for (i = 0; i < MAX_REGIONS; i++) {
		key = p[i] * MAX_THREAD * 3 + id * 3 + switcher[si][2];
		kmem[0] = key;

		tx = txn_alloc(false);
		assert(!IS_ERR(tx));
		err = bt_del(tx, t, &k);
		if (!err) {
			assert(bitmap[key >> 3] & (1 << (key % 8)));
			__sync_fetch_and_and(&bitmap[key >> 3],
			    ~(1U << (key % 8)));
		} else if (err == -ENOENT) {
			assert(!(bitmap[key >> 3] & (1 << (key % 8))));
		} else {
			fprintf(stderr, "error in delete\n");
		}
		err = txn_commit(tx, false);
		assert(!err);
		// txn_free(tx);
	}
	return NULL;
}

void test(void)
{
	pthread_t lthread[MAX_THREAD],ithread[MAX_THREAD],dthread[MAX_THREAD];
	uint32_t kmem[64];
	uint32_t vmem[64];
	uint32_t i;
	DBT k, v;
	int err;

	memset(kmem, 0, sizeof(kmem));
	memset(vmem, 0, sizeof(vmem));

	k.data = kmem;
	k.size = 32;
	v.data = vmem;
	v.size = 250;
	for (i = 0; i < MAX_ELE; i++) {
		kmem[0] = i;
		err = bt_get(t, &k, &v); 
		if (!err) {
			bitmap[i / 8] |= (1 << (i % 8));
		} else {
			assert(err == -ENOENT);
		}
	}
	for (i = 0; i < 10; i++)  {
		unsigned long j;
		fprintf(stdout, "START:%d...", i);
		srandom(i);
		for (j = 0; j < MAX_THREAD; j++)
			pthread_create(&lthread[j], NULL, looker,   (void*) j);
		for (j = 0; j < MAX_THREAD; j++)
			pthread_create(&ithread[j], NULL, inserter, (void*) j);
		for (j = 0; j < MAX_THREAD; j++)
			pthread_create(&dthread[j], NULL, deleter,  (void*) j);
		for (j = 0; j < MAX_THREAD; j++)
			pthread_join(lthread[j], NULL);
		for (j = 0; j < MAX_THREAD; j++)
			pthread_join(ithread[j], NULL);
		for (j = 0; j < MAX_THREAD; j++)
			pthread_join(dthread[j], NULL);
		fprintf(stdout, "DONE.\n");
		si = (si + 1) % 6;
	}
}

int main(int argc, char **argv)
{
	struct super_block sb;
	int fd;
	int err;

	if ((fd = open(argv[1], O_RDWR|O_CREAT, 0755)) <= 0) {
		fprintf(stderr, "Open failed (%s)\n", strerror(errno));
		return (-errno);
	}

	if (sizeof(struct super_block) != pread(fd, &sb,
	    sizeof(struct super_block), 0))
		return -EIO;
	
	if (sb.magic != SB_MAGIC)
		return -EIO;

	if ((err = lm_system_init(fd, sb.lm_log_off)))
		return err;
	if ((err = rm_system_init(fd)))
		return err;
	if ((err = mm_system_init(512 + 256)))
		return err;
	if ((err = tx_system_init(fd)))
		return err;
	if ((err = pm_system_init(fd)))
		return err;
	if ((err = bm_system_init(fd)))
		return err;
	if ((err = bt_system_init(fd)))
		return err;

	if (!IS_ERR(t = bt_alloc()))
		test();

	bt_system_exit();
	bm_system_exit();
	pm_system_exit();
	tx_system_exit();
	rm_system_exit();
	lm_system_exit();
	return 0;
}
