#include "txn_int.h"

static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list_head gbl_ops; 
static uint64_t txn_next_id;
static uint64_t txn_next_lsn;

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
	return tx;
}

int
txn_log_ins(struct txn *tx, uint64_t pgno, uint64_t lsn, void *rec,
    size_t rec_len, int ins_idx, uint64_t *out_lsn)
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

	*out_lsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

int
txn_log_del(struct txn *tx, uint64_t pgno, uint64_t lsn, void *rec,
    size_t rec_len, int del_idx, uint64_t *out_lsn)
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

	*out_lsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

int
txn_log_rep(struct txn *tx, uint64_t pgno, uint64_t lsn, void *rec,
    size_t rec_len, void *key, size_t key_len, void *val, size_t val_len,
    int rep_idx, uint64_t *out_lsn)
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

	*out_lsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

static int
__txn_log_split_old(struct txn *tx, uint64_t ppgno, uint64_t plsn,
    uint64_t opgno, uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int idx,
    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn)
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

	*out_olsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

static int
__txn_log_split_left(struct txn *tx, uint64_t ppgno, uint64_t plsn,
    uint64_t opgno, uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int idx,
    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn)
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
	
	*out_llsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

static int
__txn_log_split_right(struct txn *tx, uint64_t ppgno, uint64_t plsn,
    uint64_t opgno, uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int idx,
    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn)
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

	*out_rlsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

static int
__txn_log_split_parent(struct txn *tx, uint64_t ppgno, uint64_t plsn,
    uint64_t opgno, uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int ins_idx,
    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn)
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

	*out_plsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);

	return 0;
}

int
txn_log_split(struct txn *tx, uint64_t ppgno, uint64_t plsn, uint64_t opgno,
    uint64_t olsn, uint64_t lpgno, uint64_t rpgno, int ins_idx, int spl_idx,
    uint64_t *out_olsn, uint64_t *out_plsn, uint64_t *out_llsn, 
    uint64_t *out_rlsn)
{
	int ret;

	if ((ret = __txn_log_split_old(tx, ppgno, plsn, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn))) 
		return ret;
	if ((ret = __txn_log_split_left(tx, ppgno, plsn, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn))) 
		return ret;
	if ((ret = __txn_log_split_right(tx, ppgno, plsn, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn))) 
		return ret;
	if ((ret = __txn_log_split_parent(tx, ppgno, plsn, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn))) 
		return ret;
	return 0;
}

int
txn_log_newroot(struct txn *tx, uint64_t ppgno, uint64_t opgno, uint64_t olsn,
    uint64_t lpgno, uint64_t rpgno, uint64_t mdpgno, uint64_t mdlsn,
    int ins_idx, int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn,
    uint64_t *out_llsn, uint64_t *out_rlsn, uint64_t *out_mdlsn)
{
	struct pgmop *mop;
	struct pgop_split_md *dop;
	int ret;

	if ((ret = __txn_log_split_old(tx, ppgno, 0, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn))) 
		return ret;
	if ((ret = __txn_log_split_left(tx, ppgno, 0, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn))) 
		return ret;
	if ((ret = __txn_log_split_right(tx, ppgno, 0, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn))) 
		return ret;
	if ((ret = __txn_log_split_parent(tx, ppgno, 0, opgno, olsn, lpgno,
	    rpgno, ins_idx, spl_idx, out_olsn, out_plsn, out_llsn, out_rlsn))) 
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

	*out_mdlsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

int
txn_log_bmop(struct txn *tx, uint64_t pgno, uint64_t lsn, int bu, int bit,
    bool set, uint64_t *out_lsn)
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

	*out_lsn = dop->lsn;
	pthread_mutex_lock(&list_lock);
	list_add(&mop->lgops, &gbl_ops);
	pthread_mutex_unlock(&list_lock);
	return 0;
}

static int oplg_fd, pglg_fd;
static loff_t oplg_off, pglg_off;

int
lg_flush(void)
{
	struct pgmop *mop;
	struct iovec iov[256];
	struct list_head list;
	int i = 0, len = 0, ret;
	size_t b;
	loff_t saved_lgoff = oplg_off;
	static pthread_mutex_t iolock = PTHREAD_MUTEX_INITIALIZER; 

	INIT_LIST_HEAD(&list);

	pthread_mutex_lock(&list_lock);
	list_for_each_entry(mop, &gbl_ops, lgops) 
		assert(mop->size < 1000);

	list_splice(&gbl_ops, &list);
	INIT_LIST_HEAD(&gbl_ops);
	pthread_mutex_unlock(&list_lock);

	if (list_empty(&list))
		return 0;

	pthread_mutex_lock(&iolock);
	list_for_each_entry(mop, &list, lgops) {
		assert(mop->size < 1000);
		iov[i].iov_base = mop->dop;
		iov[i].iov_len = mop->size;
		len += mop->size;
		if (++i < 256)
			continue;
		if (len != (b = pwritev(oplg_fd, iov, 256, oplg_off))) {
			pthread_mutex_lock(&list_lock);
			list_splice(&list, &gbl_ops);
			pthread_mutex_unlock(&list_lock);
			oplg_off = saved_lgoff;
			pthread_mutex_unlock(&iolock);
			assert(0);
			return -EIO;
		}
		oplg_off += len;
		i = 0;
		len = 0;
	}

	if (i && (len != (b = pwritev(oplg_fd, iov, i, oplg_off)))) {
		pthread_mutex_lock(&list_lock);
		list_splice(&list, &gbl_ops);
		pthread_mutex_unlock(&list_lock);
		oplg_off = saved_lgoff;
		pthread_mutex_unlock(&iolock);
		assert(0);
		return -EIO;
	}
	if ((ret = fsync(oplg_fd))) {
		pthread_mutex_lock(&list_lock);
		list_splice(&list, &gbl_ops);
		pthread_mutex_unlock(&list_lock);
		oplg_off = saved_lgoff;
		pthread_mutex_unlock(&iolock);
		assert(0);
		return ret;
	}
	oplg_off += len;
	pthread_mutex_unlock(&iolock);
	return 0;
}

int
txn_commit(struct txn *tx)
{
	int ret;
	size_t b;
	struct tx_commit_rec cr;

	if ((ret = lg_flush()))
		return ret;

	cr.magic = * (uint64_t *) ("COMMITTX");
	cr.txid = tx->id;
	if (sizeof (struct tx_commit_rec) != 
	    (b = pwrite(oplg_fd, &cr, sizeof (struct tx_commit_rec),
	    oplg_off))) {
		assert(0);
		return -EIO;
	}
	if ((ret = fsync(oplg_fd)))
		return ret;
	oplg_off += sizeof (struct tx_commit_rec);
	return 0;
}

int
txn_commit_page(uint64_t pgno, void *pg, size_t len)
{
	int ret;
	size_t b;
	struct tx_commit_rec cr;

	if ((ret = lg_flush())) 
		return ret;
	if (len != (b = pwrite(pglg_fd, pg, len, pglg_off)))
		return -EIO;
	if ((ret = fsync(pglg_fd))) 
		return ret;

	cr.magic = * (uint64_t *) ("COMMITPG");
	cr.txid = pgno;
	if (sizeof (struct tx_commit_rec) != 
	    (b = pwrite(pglg_fd, &cr, sizeof (struct tx_commit_rec), 
	    pglg_off + len)))
		return -EIO;
	if ((ret = fsync(pglg_fd)))
		return ret;
	pglg_off += len + sizeof (struct tx_commit_rec);
	return 0;
}

void
txn_system_exit(void)
{
	if (oplg_fd > 0)
		close(oplg_fd);
	if (pglg_fd > 0)
		close(pglg_fd);
}

int
txn_system_init(void)
{
	INIT_LIST_HEAD(&gbl_ops);
	if ((oplg_fd = open("/tmp/oplog", O_RDWR|O_CREAT, 0755)) < 0)
		return oplg_fd;
	if ((pglg_fd = open("/tmp/pglog", O_RDWR|O_CREAT, 0755)) < 0)
		return pglg_fd;
	return 0;
}
