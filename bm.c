#include "global.h"
#include "bm_int.h"

#include "find_bit.c"

static uint64_t *maps[MAX_UNIT_TYPE + 1];

static long
__blk_alloc(struct mpage *mp, uint64_t unit, uint64_t *map, int shft)
{
	unsigned long bit;
	struct dpage *dp;
	struct bunit *bu;

	pthread_mutex_lock(&mp->mutex);
	dp = mp->dp;
	bu = &dp->bu[unit % DP_NBUNIT];
	if (bu->shft == MAX_UNIT_SHFT && bu->nfree) {
		bu->shft = shft;
		bu->nmax = bu->nfree = 1UL << (MAX_UNIT_SHFT - shft);
		bu->nfree--;
		set_bit(unit, map);
		clear_bit(unit, maps[MAX_UNIT_TYPE]);
		bit = 0;
	} else if (bu->shft == shft && bu->nfree) {
		bit = find_next_zero_bit(bu->map, bu->nmax, 0);
		if (--bu->nfree == 0)
			clear_bit(unit, map);
	} else {
		pthread_mutex_unlock(&mp->mutex);
		return (-EAGAIN);
	}
	set_bit(bit, bu->map);
	pthread_mutex_unlock(&mp->mutex);
	return ((unit << MAX_UNIT_SHFT) + (bit << shft));
}

long
bm_blk_alloc(int shft)
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
		ret = __blk_alloc(mp, unit, map, shft);
		bm_page_put(mp);
	} while (ret == -EAGAIN);

	return (ret);
}

int
bm_blk_free(blk_t blk)
{
	unsigned long unit = blk >> MAX_UNIT_SHFT;
	unsigned long pgno = unit / DP_NBUNIT;
	struct mpage *mp;
	struct dpage *dp;
	struct bunit *bu;

	mp = bm_page_get(pgno);
	if (IS_ERR(mp))
		return (PTR_ERR(mp));
	pthread_mutex_lock(&mp->mutex);
	dp = mp->dp;
	bu = &dp->bu[unit % DP_NBUNIT];
	clear_bit(BLK2BIT(bu, blk), bu->map);
	bu->nfree++;
	if (bu->nfree == bu->nmax) {
		clear_bit(unit, maps[bu->shft - MIN_UNIT_SHFT]);
		bu->shft = MAX_UNIT_SHFT;
		bu->nfree = bu->nmax = 1;
		set_bit(unit, maps[MAX_UNIT_TYPE]);
	} else if (bu->nfree == 1) {
		set_bit(unit, maps[bu->shft - MIN_UNIT_SHFT]);
	}
	pthread_mutex_unlock(&mp->mutex);
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

int
bm_system_init(void)
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

		blocks[i] = bm_blk_alloc(sizes[i]);
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
	for (i = i - 1; i >= 0; i--)
		if (sizes[i])
			bm_blk_free(blocks[i]);

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
	bm_system_init();

	test();
	return (0);
}
#endif

#ifdef MKFS
static int 
mkb(int fd)
{
	int i;
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
		bwrote = pwrite(fd, dp, BLK_SIZE, (i + 1) << BLK_SHFT);
		if (bwrote != BLK_SIZE)
			return (-EIO);
	}
	bu_nbits = 1UL << (MAX_UNIT_SHFT - MIN_UNIT_SHFT);
	pg_nbits = DP_NBUNIT * bu_nbits;
	
	npgs = (MAX_BUPAGES + 1) / pg_nbits;
	nbus = (MAX_BUPAGES + 1 - npgs * pg_nbits) / bu_nbits; 
	nbits = (MAX_BUPAGES + 1 - npgs * pg_nbits - nbus * bu_nbits);

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
		bwrote = pwrite(fd, dp, BLK_SIZE, (i + 1) << BLK_SHFT);
		if (bwrote != BLK_SIZE)  
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
	bwrote = pwrite(fd, dp, BLK_SIZE, (npgs + 1) << BLK_SHFT);
	if (bwrote != PAGE_SIZE)  
		return (-EIO);
	return (fsync(fd));
}

int 
main(int argc, char **argv)
{
	int fd, ret;

	fd = open(argv[1], O_RDWR|O_CREAT, 0755);
	if (fd <= 0) {
		fprintf(stderr, "Open failed (%s)\n", strerror(errno));
		return -errno;
	}
	ret = mkb(fd);
	close(fd);
	return ret;
}
#endif
