#include "bm_int.h"

static pg_mgr_t *pm;

void
bm_page_rdlock(struct mpage *mp)
{
	pm_page_rdlock(pm, mp);
}

void
bm_page_wrlock(struct mpage *mp)
{
	pm_page_wrlock(pm, mp);
}

void
bm_page_wrlock_nocow(struct mpage *mp)
{
	pm_page_wrlock_nocow(pm, mp);
}

void
bm_page_unlock(struct mpage *mp)
{
	pm_page_unlock(pm, mp);
}

void
bm_page_mark_dirty(struct mpage *mp)
{
	pm_page_mark_dirty(pm, mp);
}

struct mpage *
bm_page_get_nowait(pgno_t pgno)
{
	return pm_page_get_nowait(pm, pgno + BM_PREMAP_PGS);
}

struct mpage *
bm_page_get(pgno_t pgno)
{
	return pm_page_get(pm, pgno + BM_PREMAP_PGS);
}

void
bm_page_put(struct mpage *mp)
{
	return pm_page_put(pm, mp);
}

int
bm_txn_log_bmop(struct txn *tx, struct mpage *mp, int bu, int bit, bool set)
{
	return pm_txn_log_bmop(pm, tx, mp, bu, bit, set);
}

static int
__init_mpage(struct mpage *mp)
{
	if (!(mp->lockmap_dp = malloc(mp->size)))
		return -ENOMEM;
	pthread_mutex_init(&mp->mutex, NULL);
	return 0;
}

static void
__read_mpage(struct mpage *mp)
{
	memcpy(mp->lockmap_dp, mp->dp, mp->size);
}

static void
__exit_mpage(struct mpage *mp, bool deleted)
{
	if (mp->lockmap_dp)
		free(mp->lockmap_dp);
	return;	
}

void
bm_page_system_exit(void)
{
	if (pm)
		pm_free(pm);
}

int 
bm_page_system_init(void)
{
	if (IS_ERR(pm = pm_alloc(sizeof (struct mpage), __init_mpage,
	    __read_mpage, __exit_mpage, 100)))
		return PTR_ERR(pm);
	return 0;
}
