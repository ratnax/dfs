#include "tx_int.h"

static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list_head gbl_ops; 
static uint64_t txn_next_id;
static uint64_t txn_next_lsn;
static struct list_head full_logs;
static struct list_head active_logs;

static int kk, kkk1, kkkk;
static pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;
uint64_t txn_get_next_lsn(void)
{
	uint64_t lsn;
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&mutex);
	lsn = txn_next_lsn++;
	pthread_mutex_unlock(&mutex);

	return lsn;
}

void txn_free(struct txn *tx)
{
	free(tx);
	pthread_mutex_lock(&_mutex);
	kkk1++;
	pthread_mutex_unlock(&_mutex);

}

struct txn *txn_alloc(void)
{
	struct txn *tx;
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	if (!(tx = malloc(sizeof (struct txn)))) 
		return ERR_PTR(-ENOMEM);

	pthread_mutex_lock(&mutex);
	tx->id = txn_next_id++;
	pthread_mutex_unlock(&mutex);
	INIT_LIST_HEAD(&tx->mops);
	tx->ncommited = 0;
	tx->ntotal = 0;
	tx->omp = NULL;
	tx->pm = NULL;

	pthread_mutex_lock(&_mutex);
	kk++;
	pthread_mutex_unlock(&_mutex);
	return tx;
}

int
txn_log_ins(struct txn *tx, uint64_t pgno, uint64_t lsn, void *rec,
    size_t rec_len, int ins_idx, uint64_t *out_lsn, struct pgmop **out_mop)
{
	struct pgmop *mop;
	struct pgop_insert *dop;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct pgop_insert) + rec_len)))
		return -ENOMEM;

	dop = (struct pgop_insert *) mop->dop;
	dop->pgno = pgno;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = lsn;
	dop->txid = tx->id;
	dop->type = PGOP_INSERT;
	dop->ins_idx = ins_idx;
	dop->rec_len = rec_len;
	memcpy(dop->bytes, rec, rec_len);
	mop->size = sizeof (struct pgop_insert) + rec_len;
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;

	*out_lsn = dop->lsn;
	*out_mop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	list_add(&mop->txops, &tx->mops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

int
txn_log_del(struct txn *tx, uint64_t pgno, uint64_t lsn, void *rec,
    size_t rec_len, int del_idx, uint64_t *out_lsn, struct pgmop **out_mop)
{
	struct pgmop *mop;
	struct pgop_delete *dop;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct pgop_delete) + rec_len)))
		return -ENOMEM;

	dop = (struct pgop_delete *) mop->dop;
	dop->pgno = pgno;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = lsn;
	dop->txid = tx->id;
	dop->type = PGOP_DELETE;
	dop->del_idx = del_idx;
	dop->rec_len = rec_len;
	memcpy(dop->bytes, rec, rec_len);
	mop->size = sizeof (struct pgop_delete) + rec_len;
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;

	*out_lsn = dop->lsn;
	*out_mop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->txops, &tx->mops);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

int
txn_log_rep(struct txn *tx, uint64_t pgno, uint64_t lsn, void *rec,
    size_t rec_len, void *key, size_t key_len, void *val, size_t val_len,
    int rep_idx, uint64_t *out_lsn, struct pgmop **out_mop)
{
	struct pgmop *mop;
	struct pgop_replace *dop;

	if (!(mop = malloc(sizeof (struct pgmop) + 
	    sizeof (struct pgop_replace) + rec_len + key_len + val_len)))
		return -ENOMEM;

	dop = (struct pgop_replace *) mop->dop;
	dop->pgno = pgno;
	dop->txid = tx->id;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = lsn;
	dop->type = PGOP_REPLACE;
	dop->rep_idx = rep_idx;
	dop->rec_len = rec_len;
	dop->key_len = key_len;
	dop->val_len = val_len;
	memcpy(dop->bytes, rec, rec_len);
	memcpy((void *) (dop->bytes) + rec_len, key, key_len);
	memcpy((void *) (dop->bytes) + rec_len + key_len, val, val_len);
	mop->size = sizeof (struct pgop_replace) + rec_len + key_len + val_len;
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;

	*out_lsn = dop->lsn;
	*out_mop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	list_add(&mop->txops, &tx->mops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

#if 0
static int
__txn_log_split_old(struct txn *tx, uint64_t ppgno, uint64_t plsn,
    uint64_t opgno, uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int idx,
    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn, struct pgmop **out_omop, struct pgmop **out_lmop,
    struct pgmop **out_rmop, struct pgmop **out_pmop)
{
	struct pgmop *mop;
	struct pgop_split_old *dop;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct pgop_split_old))))
		return -ENOMEM;

	dop = (struct pgop_split_old *) mop->dop;
	dop->pgno = opgno;
	dop->txid = tx->id;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = olsn;
	dop->type = PGOP_SPLIT_OLD;
	dop->lpgno = lpgno;
	dop->rpgno = rpgno;
	dop->spl_idx = spl_idx;
	mop->size = sizeof (struct pgop_split_old);
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;

	*out_olsn = dop->lsn;
	*out_omop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	list_add(&mop->txops, &tx->mops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}
#endif

static int
__txn_log_split_left(struct txn *tx, uint64_t ppgno, uint64_t plsn,
    uint64_t opgno, uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int idx,
    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn, struct pgmop **out_omop, struct pgmop **out_lmop,
    struct pgmop **out_rmop, struct pgmop **out_pmop)
{
	struct pgmop *mop;
	struct pgop_split_left *dop;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct pgop_split_left))))
		return -ENOMEM;

	dop = (struct pgop_split_left *) mop->dop;
	dop->pgno = lpgno;
	dop->txid = tx->id;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = 0;
	dop->type = PGOP_SPLIT_LEFT;
	dop->spl_idx = spl_idx;
	dop->olsn = olsn;
	dop->opgno = opgno;
	mop->size = sizeof (struct pgop_split_left);
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;
	
	*out_llsn = dop->lsn;
	*out_lmop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	list_add(&mop->txops, &tx->mops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

static int
__txn_log_split_right(struct txn *tx, uint64_t ppgno, uint64_t plsn,
    uint64_t opgno, uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int idx,
    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn, struct pgmop **out_omop, struct pgmop **out_lmop,
    struct pgmop **out_rmop, struct pgmop **out_pmop)
{
	struct pgmop *mop;
	struct pgop_split_right *dop;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct pgop_split_right))))
		return -ENOMEM;

	dop = (struct pgop_split_right *) mop->dop;
	dop->pgno = rpgno;
	dop->txid = tx->id;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = 0;
	dop->type = PGOP_SPLIT_RIGHT;
	dop->spl_idx = spl_idx;
	dop->olsn = olsn;
	dop->opgno = opgno;
	mop->size = sizeof (struct pgop_split_right);
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;

	*out_rlsn = dop->lsn;
	*out_rmop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	list_add(&mop->txops, &tx->mops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

static int
__txn_log_split_parent(struct txn *tx, uint64_t ppgno, uint64_t plsn,
    uint64_t opgno, uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int ins_idx,
    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn, struct pgmop **out_omop, struct pgmop **out_lmop,
    struct pgmop **out_rmop, struct pgmop **out_pmop)
{
	struct pgmop *mop;
	struct pgop_split_parent *dop;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct pgop_split_parent))))
		return -ENOMEM;

	dop = (struct pgop_split_parent *) mop->dop; 
	dop->pgno = ppgno;
	dop->txid = tx->id;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = plsn;
	dop->type = PGOP_SPLIT_PARENT;
	dop->ins_idx = ins_idx;
	dop->spl_idx = spl_idx;
	dop->olsn = olsn;
	dop->opgno = opgno;
	dop->lpgno = lpgno;
	dop->rpgno = rpgno;
	mop->size = sizeof (struct pgop_split_parent);
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;

	*out_plsn = dop->lsn;
	*out_pmop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	list_add(&mop->txops, &tx->mops);
	pthread_mutex_unlock(&list_lock);

	return 0;
}

int
txn_log_split(struct txn *tx, uint64_t ppgno, uint64_t plsn, uint64_t opgno,
    uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int ins_idx, int spl_idx,
    uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn, struct pgmop **out_omop, struct pgmop **out_lmop,
    struct pgmop **out_rmop, struct pgmop **out_pmop)
{
	int ret;

#if 0
	if ((ret = __txn_log_split_old(tx, ppgno, plsn, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn,
	    out_omop, out_lmop, out_rmop, out_pmop))) 
		return ret;
#endif
	if ((ret = __txn_log_split_left(tx, ppgno, plsn, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn,
	    out_omop, out_lmop, out_rmop, out_pmop))) 
		return ret;
	if ((ret = __txn_log_split_right(tx, ppgno, plsn, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn,
	    out_omop, out_lmop, out_rmop, out_pmop))) 
		return ret;
	if ((ret = __txn_log_split_parent(tx, ppgno, plsn, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn,
	    out_omop, out_lmop, out_rmop, out_pmop))) 
		return ret;
	return 0;
}

int
txn_log_newroot(struct txn *tx, uint64_t ppgno, uint64_t opgno, uint64_t olsn,
    uint64_t lpgno, uint64_t rpgno, uint64_t mdpgno, uint64_t mdlsn,
    int ins_idx, int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn,
    uint64_t *out_llsn, uint64_t *out_rlsn, uint64_t *out_mdlsn,
    struct pgmop **out_omop, struct pgmop **out_lmop, struct pgmop **out_rmop,
    struct pgmop **out_pmop, struct pgmop **out_mdmop)
{
	struct pgmop *mop;
	struct pgop_split_md *dop;
	int ret;

#if 0
	if ((ret = __txn_log_split_old(tx, ppgno, 0, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn,
	    out_omop, out_lmop, out_rmop, out_pmop))) 
		return ret;
#endif
	if ((ret = __txn_log_split_left(tx, ppgno, 0, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn,
	    out_omop, out_lmop, out_rmop, out_pmop))) 
		return ret;
	if ((ret = __txn_log_split_right(tx, ppgno, 0, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn,
	    out_omop, out_lmop, out_rmop, out_pmop))) 
		return ret;
	if ((ret = __txn_log_split_parent(tx, ppgno, 0, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn,
	    out_omop, out_lmop, out_rmop, out_pmop))) 
		return ret;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct pgop_split_md))))
		return -ENOMEM;

	dop = (struct pgop_split_md *) mop->dop; 
	dop->pgno = ppgno;
	dop->txid = tx->id;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = mdlsn;
	dop->type = PGOP_SPLIT_MD;
	dop->opgno = opgno;
	dop->npgno = ppgno;
	mop->size = sizeof (struct pgop_split_parent);
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;

	*out_mdlsn = dop->lsn;
	*out_mdmop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	list_add(&mop->txops, &tx->mops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

int
txn_log_bmop(struct txn *tx, uint64_t pgno, uint64_t lsn, int bu, int bit,
    bool set, uint64_t *out_lsn, struct pgmop **out_mop)
{
	struct pgmop *mop;
	struct pgop_blkop *dop;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct pgop_blkop))))
		return -ENOMEM;

	dop = (struct pgop_blkop *) mop->dop;
	dop->pgno = pgno;
	dop->txid = tx->id;
	dop->lsn = txn_get_next_lsn();
	dop->prev_lsn = lsn;
	dop->type = set ? PGOP_BLKSET : PGOP_BLKRESET;
	dop->bu = bu;
	dop->bit = bit;
	mop->size = sizeof (struct pgop_blkop);
	mop->tx = tx;
	mop->pg = NULL;
	mop->tx_commited = mop->pg_commited = false;
	tx->ntotal++;

	*out_lsn = dop->lsn;
	*out_mop = mop;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	list_add(&mop->txops, &tx->mops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

static int oplg_fd, pglg_fd;
static loff_t oplg_off, pglg_off;

void
txn_free_op(struct pgmop *mop)
{
	log_put(mop->lg);
	list_del(&mop->txops);
	list_del(&mop->pgops);
	free(mop);
}

static int
__tx_ops_flush(void)
{
	lm_log_t *lg;
	struct pgmop *mop;
	struct list_head list;

	INIT_LIST_HEAD(&list);

	pthread_mutex_lock(&list_lock);
	list_splice(&gbl_ops, &list);
	INIT_LIST_HEAD(&gbl_ops);
	pthread_mutex_unlock(&list_lock);

	if (list_empty(&list))
		return 0;

	list_for_each_entry(mop, &list, lgops) {
		if (IS_ERR(lg = lm_write(mop->dop, mop->size))) {
			return PTR_ERR(lg);
		}
		mop->lg = lg;
	}
	return 0;
}

static struct tx_commit_rec cr[1024];
static int cri;
static pthread_mutex_t iolock = PTHREAD_MUTEX_INITIALIZER;

static int
__tx_commit(struct txn *tx)
{
	lm_log_t *lg;
	struct tx_commit_rec *cr;
	int ret;
	struct pgmop *mop, *tmp;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct tx_commit_rec))))
		return -ENOMEM;

	cr = (struct tx_commit_rec *) mop->dop;
	mop->size = sizeof (struct tx_commit_rec);
	if ((ret = __tx_ops_flush()))
		return ret;

	cr->type = PGOP_COMMIT_TXN;
	cr->txid = tx->id;
	if (IS_ERR(lg = lm_write(cr, sizeof(struct tx_commit_rec))))
		return PTR_ERR(lg);
	if ((ret = lm_commit()))
		return ret;
	mop->lg = lg;	
	tx->mop = mop;
	list_for_each_entry_safe(mop, tmp, &tx->mops, txops) {
		mop->tx_commited = true;
		list_del(&mop->txops);
		if (mop->pg_commited) {
			log_put(mop->lg);
			free(mop);
			tx->ncommited++;
		}
	}
	if (tx->ncommited == tx->ntotal) {
		log_put(tx->mop->lg);
		free(tx->mop);
		tx->mop = NULL;
		assert(list_empty(&tx->mops));
		if (tx->omp)
			pm_page_put(tx->pm, tx->omp);
		txn_free(tx);
	}
	return ret;
}

int
txn_commit(struct txn *tx)
{
	int ret;

	pthread_mutex_lock(&iolock);
	ret = __tx_commit(tx);
	pthread_mutex_unlock(&iolock);
	pthread_mutex_lock(&_mutex);
	kkkk++;
	pthread_mutex_unlock(&_mutex);
	return ret;
}

static int
__tx_log_page(struct page *pg, void *dp, size_t len)
{
	lm_log_t *lg;
	struct iovec iov[2];
	struct tx_commit_rec *cr;
	struct pgmop *mop;
	int ret;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct tx_commit_rec))))
		return -ENOMEM;

	cr = (struct tx_commit_rec *) mop->dop;
	mop->size = sizeof (struct tx_commit_rec);
	if ((ret = __tx_ops_flush())) 
		return ret;
	cr->type = PGOP_COMMIT_PAGE;
	cr->pgno = pg->pgno;

	iov[0].iov_base = &cr;
	iov[0].iov_len = sizeof (struct tx_commit_rec);

	iov[1].iov_base = dp;
	iov[1].iov_len = len;

	if (IS_ERR(lg = lm_writev(iov, 2, len + sizeof(struct tx_commit_rec))))
		return PTR_ERR(lg);
	mop->lg = lg;
	if ((ret = lm_commit()))
		return ret;
	pg->mop = mop;
	do {
		mop = list_first_entry(&pg->mops, struct pgmop, pgops);
		if (!mop->size)
			break;
		list_del(&mop->pgops);
		mop->pg_commited = true;
		if (mop->tx_commited) {
			struct txn *tx = mop->tx;
			log_put(mop->lg);
			free(mop);
			tx->ncommited++;
			if (tx->ncommited == tx->ntotal) {
				log_put(tx->mop->lg);
				free(tx->mop);
				tx->mop = NULL;
				if (tx->omp)
					pm_page_put(tx->pm, tx->omp);
				assert(list_empty(&tx->mops));
				txn_free(tx);
			}
		} 
	} while (1);
	return 0;
}

int
txn_log_page(struct page *pg, void *dp, size_t len)
{
	int ret;

	pthread_mutex_lock(&iolock);
	ret = __tx_log_page(pg, dp, len);
	pthread_mutex_unlock(&iolock);
	return ret;
}

int
txn_commit_page(struct page *pg, int err)
{
	pthread_mutex_lock(&iolock);
	log_put(pg->mop->lg);
	pthread_mutex_unlock(&iolock);
	free(pg->mop);
	pg->mop = NULL;
	return err;
}

void
tx_system_exit(void)
{
	return;
}

int
tx_system_init(int fd)
{
	INIT_LIST_HEAD(&gbl_ops);
	return 0;
}
