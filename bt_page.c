#include "pm_ext.h"
#include "bt_int.h"

static pg_mgr_t *pm;

struct txn *bt_txn_alloc(bool sys)
{
	return txn_alloc(sys);
}

void bt_txn_free(struct txn *tx)
{
	txn_free(tx);
}

enum { OP_INS, OP_DEL, OP_IDEL, OP_REP, OP_SPL, OP_RSPL };

struct ins_leaf_op {
	uint8_t		op;
	uint8_t		dbid;
	uint16_t	ins_idx;
	uint16_t	rec_len;
	uint8_t		bytes[0];
};

struct del_leaf_op {
	uint8_t		op;
	uint8_t		dbid;
	uint16_t	ins_idx;
	uint16_t	rec_len;
	uint8_t		bytes[0];
};

struct del_internal_op {
	uint8_t		op;
	uint8_t		dbid;
	uint16_t	del_idx;
	uint16_t	rec_len;
	uint8_t		bytes[0];
};

struct spl_op {
	uint8_t		op;
	uint8_t		dbid;
	uint16_t	ins_idx;
	uint16_t	spl_idx;
};

struct rspl_op {
	uint8_t		op;
	uint8_t		dbid;
	uint16_t	ins_idx;
	uint16_t	spl_idx;
};


int
bt_txn_log_ins_leaf(struct txn *tx, struct mpage *mp, int ins_idx)
{
	DLEAF *dl = GETDLEAF(mp->dp, ins_idx);
	int n = NDLEAF(dl);
	struct ins_leaf_op	*p;
	size_t len = sizeof (struct ins_op) + n;

	if (!(p = malloc(len)))
		return -ENOMEM;

	p->op = OP_INS;
	p->dbid = 0;
	p->ins_idx = ins_idx;
	p->rec_len = n;
	memcpy(p->bytes, dl, n);
	return pm_txn_log_op(pm, tx, p, len, 1, 0, mp);
}

int
bt_txn_log_del_leaf(struct txn *tx, struct mpage *mp, int del_idx)
{
	DLEAF *dl = GETDLEAF(mp->dp, del_idx);
	int n = NDLEAF(dl);
	struct del_leaf_op *p;
	size_t len = sizeof (struct del_leaf_op) + n;

	if (!(p = malloc(len)))
		return -ENOMEM;

	p->op = OP_DEL;
	p->dbid = 0;
	p->del_idx = del_idx;
	p->rec_len = n;
	memcpy(p->bytes, dl, n);
	return pm_txn_log_op(pm, tx, p, len, 1, 0, mp);
}

int
bt_txn_log_del_internal(struct txn *tx, struct mpage *mp, int del_idx)
{
	DINTERNAL *di = GETDINTERNAL(mp->dp, del_idx);
	int n = NDINTERNAL(di->ksize);
	struct del_internal_op *p;
	size_t len = sizeof (struct del_internal_op) + n;

	if (!(p = malloc(len)))
		return -ENOMEM;

	p->op = OP_IDEL;
	p->dbid = 0;
	p->del_idx = del_idx;
	p->rec_len = n;
	memcpy(p->bytes, di, n);
	return pm_txn_log_op(pm, tx, p, len, 1, 0, mp);
}

int
bt_txn_log_rep_leaf(struct txn *tx, struct mpage *mp, DBT *key, DBT *val,
    int rep_idx)
{
	DLEAF *dl = GETDLEAF(mp->dp, rep_idx);
	int n = NDLEAF(dl);
	struct rep_leaf_op *p;
	size_t len = sizeof (struct rep_leaf_op) + n + key->size + val->size;

	if (!(p = malloc(len)))
		return -ENOMEM;

	p->op = OP_REP;
	p->dbid = 0;
	p->rep_idx = rep_idx;
	p->rec_len = n + key->size + val->size;
	memcpy(p->bytes, dl, n);
	memcpy(&p->bytes[n], key, key->size);
	memcpy(&p->bytes[n + key->size], val, val->size);
	return pm_txn_log_op(pm, tx, p, len, 1, 0, mp);
}

int bt_txn_log_split(struct txn *tx, struct mpage *pmp, struct mpage *mp,
    struct mpage *lmp, struct mpage *rmp, indx_t ins_idx, indx_t spl_idx)
{
	struct spl_op *p;
	size_t len = sizeof (struct spl_op);

	if (!(p = malloc(len)))
		return -ENOMEM;

	p->op = OP_SPL;
	p->dbid = 0;
	p->ins_idx = ins_idx;
	p->spl_idx = spl_idx;
	return pm_txn_log_op(pm, tx, p, len, 3, 1, pmp, lmp, rmp, mp);
}

int bt_txn_log_newroot(struct txn *tx, struct mpage *pmp, struct mpage *mp,
    struct mpage *lmp, struct mpage *rmp, struct mpage *mdmp, indx_t spl_idx)
{
	struct rspl_op *p;
	size_t len = sizeof (struct rspl_op);

	if (!(p = malloc(len)))
		return -ENOMEM;

	p->op = OP_RSPL;
	p->dbid = 0;
	p->spl_idx = spl_idx;
	return pm_txn_log_op(pm, tx, p, len, 3, 1, pmp, lmp, rmp, mdmp, mp);
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

static int 
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
	if (IS_ERR(pm = pm_alloc(PM_TYPE_BT, sizeof (struct mpage), 
	    &__init_mpage, &__read_mpage, &__exit_mpage, 0)))
		return (PTR_ERR(pm));
	return (0);
}
