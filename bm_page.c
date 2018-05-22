#include "bm_int.h"

static pg_mgr_t *pm;

void
bm_page_rdlock(struct mpage *mp)
{
	pm_page_rdlock(pm, mp);
}

int
bm_page_wrlock(struct txn *tx, struct mpage *mp)
{
	return pm_page_wrlock(pm, tx, mp);
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

enum { OP_SET, OP_RST };

struct bm_op {
	uint8_t op;
	uint32_t bu;
	uint32_t bit;
};

int
bm_txn_log_bmop(struct txn *tx, struct mpage *mp, int bu, int bit, bool set)
{
	struct bm_op *p;
	size_t len = sizeof (struct bm_op);

	p = txn_mem_alloc(tx, len);
	p->op = set ? OP_SET : OP_RST;
	p->bu = bu;
	p->bit = bit;
	return pm_txn_log_op(pm, tx, len, 1, 0, mp);
}

#define HASHSIZE	100
#define	HASHKEY(pgno)	(pgno % HASHSIZE)
static struct hlist_head	hash_table[HASHSIZE];
static pthread_mutex_t hlock = PTHREAD_MUTEX_INITIALIZER;

static void
__put_ldp(struct locked_dp *ldp, pgno_t pgno)
{
	pthread_mutex_lock(&hlock);
	assert(ldp->count);
	if (--ldp->count == 0) {
		hlist_del(&ldp->hq);
		free(ldp);
	}
	pthread_mutex_unlock(&hlock);
}

static struct locked_dp *
__get_ldp(pgno_t pgno, struct dpage *dp, size_t size)
{
	struct hlist_head *head;
	struct locked_dp *ldp;

	pthread_mutex_lock(&hlock);
	head = &hash_table[HASHKEY(pgno)];
	hlist_for_each_entry(ldp, head, hq) {
		if (ldp->pgno == pgno) {
			ldp->count++;
			pthread_mutex_unlock(&hlock);
			return ldp;
		}
	}
	if (!(ldp = malloc(sizeof (struct locked_dp) + size))) {
		pthread_mutex_unlock(&hlock);
		return ERR_PTR(-ENOMEM);
	}
	ldp->pgno = pgno;
	ldp->count = 1;
	ldp->dp = (struct dpage *) (ldp + 1);
	memcpy(ldp->dp, dp, size);
	hlist_add_head(&ldp->hq, head);
	pthread_mutex_unlock(&hlock);
	return ldp;
}

static int
__init_mpage(struct mpage *mp)
{
	mp->ldp = NULL;
	pthread_mutex_init(&mp->mutex, NULL);
	return 0;
}

static int 
__read_mpage(struct mpage *mp)
{
	struct locked_dp *ldp;

	if (IS_ERR(ldp = __get_ldp(mp->pgno, mp->dp, mp->size))) 
		return PTR_ERR(ldp);
	mp->ldp = ldp;
	return 0;
}

static void
__exit_mpage(struct mpage *mp, bool deleted)
{
	if (mp->ldp) {
		__put_ldp(mp->ldp, mp->pgno);
		mp->ldp = NULL;
	}
	return;	
}

void
bm_page_system_exit(void)
{
	int i;

	if (pm)
		pm_free(pm);
	for (i = 0; i < HASHSIZE; i++)
		assert(hlist_empty(&hash_table[i]));
}

int 
bm_page_system_init(void)
{
	int i;

	for (i = 0; i < HASHSIZE; i++)
		INIT_HLIST_HEAD(&hash_table[i]);

	if (IS_ERR(pm = pm_alloc(PM_TYPE_BM, sizeof (struct mpage),
	    __init_mpage, __read_mpage, __exit_mpage, 10)))
		return PTR_ERR(pm);
	return 0;
}
