#include "pm_ext.h"
#include "bt_int.h"

static pg_mgr_t *pm;

void
bt_page_mark_dirty(struct mpage *mp)
{
	pm_page_mark_dirty(pm, mp);
}

struct mpage *
bt_page_get_nowait(pgno_t pgno)
{
	return pm_page_get_nowait(pm, pgno);
}

struct mpage *
bt_page_get(pgno_t pgno)
{
	return pm_page_get(pm, pgno);
}

void
bt_page_put(struct mpage *mp)
{
	pm_page_put(pm, mp);
}

void
bt_page_free(struct mpage *mp)
{
	int err;

	pm_page_delete(pm, mp);

	err = bm_blk_free(mp->pgno);
	assert(!err);
	printf("%ld Release\n", mp->pgno);
	return;
}

struct mpage *
bt_page_new(size_t size)
{
	struct mpage *mp;
	pgno_t pgno;
 
        pgno = bm_blk_alloc(PAGE_SHFT);
	if (pgno < 0)
		return ERR_PTR(pgno);	
	printf("%ld Alloced\n", pgno);
	mp = pm_page_get_new(pm, pgno, size);
	return mp;

}

void
bt_page_rdlock(struct mpage *mp)
{
	pm_page_rdlock(pm, mp);
}

void
bt_page_wrlock(struct mpage *mp)
{
	pm_page_wrlock(pm, mp);
}

void
bt_page_unlock(struct mpage *mp)
{
	pm_page_unlock(pm, mp);
}

static int
__init_mpage(struct mpage *mp)
{
	mp->state = MP_STATE_NORMAL;
	pthread_mutex_init(&mp->mutex, NULL);
	pthread_cond_init(&mp->cond, NULL);
}

static void
__exit_mpage(struct mpage *mp)
{
	return;	
}

void
bt_page_system_exit(void)
{
	if (pm)
		pm_free(pm);
	pm = NULL;
}

int
bt_page_system_init(void)
{
	pm = pm_alloc(sizeof (struct mpage), &__init_mpage, &__exit_mpage);
	if (IS_ERR(pm))
		return (PTR_ERR(pm));
	return (0);
}
