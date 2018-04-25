#include "pm_ext.h"
#include "bt_int.h"

static pg_mgr_t *pm;

struct txn *bt_txn_alloc(void)
{
	return txn_alloc();
}

void bt_txn_free(struct txn *tx)
{
	txn_free(tx);
}

int
bt_txn_log_ins_leaf(struct txn *tx, struct mpage *mp, int ins_idx)
{
	DLEAF *dl = GETDLEAF(mp->dp, ins_idx);

	return pm_txn_log_ins(pm, tx, mp, dl, NDLEAF(dl), ins_idx);
}

int
bt_txn_log_del_leaf(struct txn *tx, struct mpage *mp, int del_idx)
{
	DLEAF *dl = GETDLEAF(mp->dp, del_idx);

	return pm_txn_log_del(pm, tx, mp, dl, NDLEAF(dl), del_idx);
}

int
bt_txn_log_del_internal(struct txn *tx, struct mpage *mp, int del_idx)
{
	DINTERNAL *di = GETDINTERNAL(mp->dp, del_idx);

	return pm_txn_log_del(pm, tx, mp, di, NDINTERNAL(di->ksize), del_idx);
}

int
bt_txn_log_rep_leaf(struct txn *tx, struct mpage *mp, DBT *key, DBT *val,
    int rep_idx)
{
	DLEAF *dl = GETDLEAF(mp->dp, rep_idx);

	return pm_txn_log_rep(pm, tx, mp, dl, NDLEAF(dl), key, key->size,
	    val, val->size, rep_idx);
}

int bt_txn_log_split(struct txn *tx, struct mpage *pmp, struct mpage *mp,
    struct mpage *lmp, struct mpage *rmp, indx_t idx, indx_t spl_idx)
{
	return pm_txn_log_split(pm, tx, pmp, mp, lmp, rmp, idx, spl_idx);
}

int bt_txn_log_newroot(struct txn *tx, struct mpage *pmp, struct mpage *mp,
    struct mpage *lmp, struct mpage *rmp, struct mpage *mdmp, indx_t spl_idx)
{
	return pm_txn_log_newroot(pm, tx, pmp, mp, lmp, rmp, mdmp, 0, spl_idx); 
}

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
bt_page_free(struct txn *tx, struct mpage *mp)
{
	int err;

	pm_page_delete(pm, mp);

	err = bm_blk_locked_free(tx, mp->pgno);
	assert(!err);
	printf("%ld Release\n", mp->pgno);
	return;
}

struct mpage *
bt_page_new(struct txn *tx, size_t size)
{
	struct mpage *mp;
	pgno_t pgno;
 
        pgno = bm_blk_alloc(tx, PAGE_SHFT);
	if (pgno < 0)
		return ERR_PTR(pgno);	
	printf("%ld Alloced\n", pgno);
	mp = pm_page_get_new(pm, pgno, size);
	return mp;

}

bool
bt_page_valid(struct mpage *mp)
{
	return bm_blk_alloced(mp->pgno);
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
	return 0;
}

static void
__read_mpage(struct mpage *mp)
{
	return;	
}

static void
__exit_mpage(struct mpage *mp, bool deleted)
{
	int err;
	if (deleted) {
		err = bm_blk_unlock(mp->pgno);
		assert(!err);
	}
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
	if (IS_ERR(pm = pm_alloc(sizeof (struct mpage), &__init_mpage,
	    &__read_mpage, &__exit_mpage, 100)))
		return (PTR_ERR(pm));
	return (0);
}
