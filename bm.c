#include "global.h"
#include "bm_int.h"

#include "find_bit.c"

static uint64_t *maps[MAX_UNIT_TYPE + 1];

static long
__blk_alloc(struct txn *tx, struct mpage *mp, uint64_t unit, uint64_t *map,
    int shft)
{
	unsigned long bit;
	struct dpage *dp, *lm_dp;
	struct bunit *bu, *lm_bu;

	bm_page_wrlock(mp);
	lm_dp = mp->lockmap_dp;
	dp = mp->dp;
	lm_bu = &lm_dp->bu[unit % DP_NBUNIT];
	bu = &dp->bu[unit % DP_NBUNIT];
	if (lm_bu->shft == MAX_UNIT_SHFT && lm_bu->nfree) {
		bu->shft = lm_bu->shft = shft;
		bu->nmax = bu->nfree = lm_bu->nmax = lm_bu->nfree = 
		    1UL << (MAX_UNIT_SHFT - shft);
		bu->nfree--;
		lm_bu->nfree--;
		set_bit(unit, map);
		clear_bit(unit, maps[MAX_UNIT_TYPE]);
		bit = 0;
	} else if (lm_bu->shft == shft && lm_bu->nfree) {
		bit = find_next_zero_bit(lm_bu->map, lm_bu->nmax, 0);
		bu->nfree--;
		lm_bu->nfree--;
		if (lm_bu->nfree == 0)
			clear_bit(unit, map);
	} else {
		bm_page_unlock(mp);
		return (-EAGAIN);
	}
	printf("%ld setting %ld in %ld:%ld\n", ((unit << MAX_UNIT_SHFT) + 
	    (bit << shft)),  bit, mp->pgno, unit % DP_NBUNIT);
	set_bit(bit, lm_bu->map);
	set_bit(bit, bu->map);
	bm_page_mark_dirty(mp);
	bm_txn_log_bmop(tx, mp, bu - dp->bu, bit, true); 
	bm_page_unlock(mp);
	return ((unit << MAX_UNIT_SHFT) + (bit << shft));
}

long
bm_blk_alloc(struct txn *tx, int shft)
{
	struct mpage *mp;
	uint64_t *map;
	uint64_t unit;
	pgno_t pgno;
	long ret;
	
	shft = shft - BLK_SHFT;
	shft = (shft < MIN_UNIT_SHFT) ? MIN_UNIT_SHFT : shft;
	map = maps[shft - MIN_UNIT_SHFT];
	do {
		unit = find_next_bit(map, TOTAL_UNITS, 0);
		if (unit >= TOTAL_UNITS) {
			unit = find_next_bit(maps[MAX_UNIT_TYPE],
			    TOTAL_UNITS, 0);
			if (unit >= TOTAL_UNITS)
				return (-ENOSPC);
		}
		pgno = unit / DP_NBUNIT;
		mp = bm_page_get(pgno);
		if (IS_ERR(mp))
			return (PTR_ERR(mp));
		ret = __blk_alloc(tx, mp, unit, map, shft);
		bm_page_put(mp);
	} while (ret == -EAGAIN);

	return (ret);
}

int
bm_blk_locked_free(struct txn *tx, blk_t blk)
{
	unsigned long unit = blk >> MAX_UNIT_SHFT;
	unsigned long pgno = unit / DP_NBUNIT;
	struct mpage *mp;
	struct dpage *dp;
	struct bunit *bu;
	int bit;

	mp = bm_page_get(pgno);
	if (IS_ERR(mp))
		return (PTR_ERR(mp));
	bm_page_wrlock(mp);
	dp = mp->dp;
	bu = &dp->bu[unit % DP_NBUNIT];
	bit = BLK2BIT(bu, blk);
	printf("%ld clearing %ld in %ld:%ld\n",
	    blk, bit, mp->pgno, unit % DP_NBUNIT);
	assert(test_bit(bit, bu->map));
	clear_bit(bit, bu->map);
	bu->nfree++;
	if (bu->nfree == bu->nmax) {
		bu->shft = MAX_UNIT_SHFT;
		bu->nfree = bu->nmax = 1;
	}
	bm_txn_log_bmop(tx, mp, bu - dp->bu, bit, false); 
	bm_page_mark_dirty(mp);
	bm_page_unlock(mp);
	bm_page_put(mp);
	return (0);
}

int
bm_blk_unlock(blk_t blk)
{
	unsigned long unit = blk >> MAX_UNIT_SHFT;
	unsigned long pgno = unit / DP_NBUNIT;
	struct mpage *mp;
	struct dpage *dp;
	struct bunit *bu;
	int bit;

	mp = bm_page_get(pgno);
	if (IS_ERR(mp))
		return (PTR_ERR(mp));
	bm_page_wrlock_nocow(mp);
	dp = mp->lockmap_dp;
	bu = &dp->bu[unit % DP_NBUNIT];
	bit = BLK2BIT(bu, blk);
	printf("%ld clearing %ld in %ld:%ld\n",
	    blk, bit, mp->pgno, unit % DP_NBUNIT);
	assert(test_bit(bit, bu->map));
	clear_bit(bit, bu->map);
	bu->nfree++;
	if (bu->nfree == bu->nmax) {
		clear_bit(unit, maps[bu->shft - MIN_UNIT_SHFT]);
		bu->shft = MAX_UNIT_SHFT;
		bu->nfree = bu->nmax = 1;
		set_bit(unit, maps[MAX_UNIT_TYPE]);
	} else if (bu->nfree == 1) {
		set_bit(unit, maps[bu->shft - MIN_UNIT_SHFT]);
	}
	bm_page_unlock(mp);
	bm_page_put(mp);
	return (0);
}

uint64_t
bm_blk_size(blk_t blk)
{
	unsigned long unit = blk >> MAX_UNIT_SHFT;
	unsigned long pgno = unit / DP_NBUNIT;
	struct mpage *mp;
	struct dpage *dp;
	struct bunit *bu;
	int ret;

	mp = bm_page_get(pgno);
	if (IS_ERR(mp))
		return (PTR_ERR(mp));
	dp = mp->dp;
	bu = &dp->bu[unit % DP_NBUNIT];
	ret = 1UL << bu->shft;
	bm_page_put(mp);
	return (ret);
}

bool
bm_blk_alloced(blk_t blk)
{
	unsigned long unit = blk >> MAX_UNIT_SHFT;
	unsigned long pgno = unit / DP_NBUNIT;
	struct mpage *mp;
	struct dpage *dp;
	struct bunit *bu;
	int ret;

	mp = bm_page_get(pgno);
	if (IS_ERR(mp))
		return (PTR_ERR(mp));

	dp = mp->dp;
	bu = &dp->bu[unit % DP_NBUNIT];
	ret = test_bit(BLK2BIT(bu, blk), bu->map);
	bm_page_put(mp);
	return (ret);
}

void bm_system_exit()
{
	bm_page_system_exit();
}

int
bm_system_init(int fd)
{
	struct mpage *mp;
	struct dpage *dp;
	struct bunit *bu;
	int i, j;
	
	bm_page_system_init();

	assert(BLK_SHFT <= PAGE_SHFT);
	for (i = 0; i <= MAX_UNIT_TYPE; i++) {
		maps[i] = calloc(TOTAL_UNITS >> 3, 1);
		if (!maps[i])
			return (-ENOMEM);
	}
	for (i = 0; i < MAX_BUPAGES; i++) {
		mp = bm_page_get(i);
		if (IS_ERR(mp)) 
			return (PTR_ERR(mp));
		dp = mp->dp;
		for (j = 0; j < DP_NBUNIT; j++) {
			bu = &dp->bu[j];
			if (!bu->nfree)
				continue;
			set_bit(i * DP_NBUNIT + j, 
			    maps[bu->shft - MIN_UNIT_SHFT]);
		}
		bm_page_put(mp);
	}
	return (0);
}

int 
bm_mkfs(int fd)
{
	int i, ret;
	char blk[BLK_SIZE];
	struct dpage *dp;
	unsigned long bu_nbits;
	unsigned long pg_nbits;
	unsigned int npgs;
	unsigned int nbus;
	unsigned int nbits;
	ssize_t bwrote;

	dp = (struct dpage *) blk;
	for (i = 0; i < DP_NBUNIT; i++) {
		dp->bu[i].shft = MAX_UNIT_SHFT;
		dp->bu[i].nmax = dp->bu[i].nfree = 1;
		memset(dp->bu[i].map, 0, sizeof (dp->bu[i].map));
	}
	printf("Total units: %llu\n", TOTAL_UNITS);
	printf("MAX_BUPAGES: %llu\n", MAX_BUPAGES);
	for (i = 0; i < MAX_BUPAGES; i++) {
		if (BLK_SIZE != (bwrote = pwrite(fd, dp, BLK_SIZE,
		    (i + BM_PREMAP_PGS) << BLK_SHFT)))
			return (-EIO);
	}
	bu_nbits = 1UL << (MAX_UNIT_SHFT - MIN_UNIT_SHFT);
	pg_nbits = DP_NBUNIT * bu_nbits;
	
	npgs = (MAX_BUPAGES + TOTAL_RSRVD_PGS) / pg_nbits;
	nbus = (MAX_BUPAGES + TOTAL_RSRVD_PGS - npgs * pg_nbits) / bu_nbits; 
	nbits = (MAX_BUPAGES + TOTAL_RSRVD_PGS - npgs * pg_nbits -
	    nbus * bu_nbits);

	printf("npgs: %u\n", npgs);
	printf("nbus: %u\n", nbus);
	printf("nbits: %u\n", nbits);

	for (i = 0; i < DP_NBUNIT; i++) {
		dp->bu[i].shft = MIN_UNIT_SHFT;
		dp->bu[i].nmax = MAX_UNIT_SIZE >> MIN_UNIT_SHFT;
		dp->bu[i].nfree = 0;
		memset(dp->bu[i].map, 0xff, sizeof (dp->bu[i].map));
	}
	for (i = 0; i < npgs; i++) {
		if (BLK_SIZE != (bwrote = pwrite(fd, dp, BLK_SIZE,
		    (i + BM_PREMAP_PGS) << BLK_SHFT)))
			return (-EIO);
	}
	if (!nbus && !nbits) 
	    return (fsync(fd));

	for (i = nbus; i < DP_NBUNIT; i++) {
		dp->bu[i].shft = MAX_UNIT_SHFT;
		dp->bu[i].nmax = dp->bu[i].nfree = 1;
		memset(dp->bu[i].map, 0, sizeof (dp->bu[i].map));
	}
	if (nbits) {
		dp->bu[nbus].shft = MIN_UNIT_SHFT;
		dp->bu[nbus].nmax = MAX_UNIT_SIZE >> MIN_UNIT_SHFT;
		dp->bu[nbus].nfree = dp->bu[nbus].nmax; 
	}
	for (i = 0; i < nbits; i++) {
		dp->bu[nbus].nfree--;
		set_bit(i, dp->bu[nbus].map); 
	}
	if (PAGE_SIZE != (bwrote = pwrite(fd, dp, BLK_SIZE,
	    (npgs + BM_PREMAP_PGS) << BLK_SHFT)))
		return (-EIO);
	if ((ret = fsync(fd)))
		return ret;
	return MAX_BUPAGES;
}

#ifdef TEST
#include <time.h>

int fd;

static void test(void)
{
#define	TEST_SIZE   50000
	int i, j, ret, k = 100;
	int sizes[TEST_SIZE];
	int64_t blocks[TEST_SIZE];
	uint64_t total = 0;
	ssize_t bread;
	struct dpage dp;

	srandom(time(NULL));
	while (k--) {

	for (i = 0; i < MAX_BUPAGES; i++) {

		bread = pread(fd, &dp, PAGE_SIZE, (i + 1) << PAGE_SHFT);
		if (bread != PAGE_SIZE)
			return;
		for (j = i ? 0 : 1; j < DP_NBUNIT; j++) {
			assert(dp.bu[j].shft == MAX_UNIT_SHFT);
			assert(dp.bu[j].nfree == 1);
			assert(dp.bu[j].nmax == 1);
		}
	}
	for (i = 0; i < TEST_SIZE; i++) {
		sizes[i] = (random() % 10) + MIN_UNIT_SHFT;

		blocks[i] = bm_blk_alloc(NULL, sizes[i]);
		if (blocks[i] < 0) {
			printf("ENOSPC at %ld %d, lost in frag %llu.\n",
			    total, i, TOTAL_SPACE - total);
			sizes[i] = 0;
			if (TOTAL_SPACE - total == 0)
				break;
		} else {
			total += 1 << sizes[i];
		}
	}
	for (i = i - 1; i >= 0; i--) {
		if (sizes[i]) {
			bm_blk_locked_free(NULL, blocks[i]);
			bm_blk_unlock(blocks[i]);
		}
	}
	for (i = 0; i < MAX_BUPAGES; i++) {
		bread = pread(fd, &dp, PAGE_SIZE, (i + 1) << PAGE_SHFT);
		if (bread != PAGE_SIZE)
			return;
		for (j = i ? 0 : 1; j < DP_NBUNIT; j++) {
			assert(dp.bu[j].shft == MAX_UNIT_SHFT);
			assert(dp.bu[j].nfree == 1);
			assert(dp.bu[j].nmax == 1);
		}
	}
	printf("allocated: %lu\n", total);
	total = 0;
	}
}

int
main()
{
	int i, j;
	struct dpage *dp = NULL;

	fd = open("/home/ratna/maps", O_RDWR|O_CREAT, 0755);
	if (fd <= 0) {
		fprintf(stderr, "Open failed (%s)\n", strerror(errno));
		return (-errno);
	}

	pm_system_init(fd);
	bm_page_system_init();
	bm_system_init(0);

	test();
	return (0);
}
#endif
