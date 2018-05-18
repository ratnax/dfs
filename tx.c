#include "tx_int.h"
#include "rm_ext.h"

static pthread_mutex_t txlock = PTHREAD_MUTEX_INITIALIZER;
static struct list_head gbl_ops; 
static struct list_head txlist; 
static uint64_t txn_next_id;
static uint64_t txn_next_lsn;
static struct list_head full_logs;
static struct list_head active_logs;
static tx_commit_cb_t g_tx_commit_cb;

int kkk=0;
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
	pthread_mutex_lock(&_mutex);
	kkk--;
	list_del(&tx->txs);
	pthread_mutex_unlock(&_mutex);

	free(tx);
}

struct txn *txn_alloc(bool sys)
{
	struct txn *tx;
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	while (!sys && kkk > 1000) { usleep(1000); } 
	if (!(tx = malloc(sizeof (struct txn)))) 
		return ERR_PTR(-ENOMEM);

	pthread_mutex_lock(&mutex);
	tx->id = txn_next_id++;
	pthread_mutex_unlock(&mutex);
	INIT_LIST_HEAD(&tx->mops);
	tx->npg_cmted = 0;
	tx->npg_total = 0;
	tx->mop = NULL;
	pthread_mutex_lock(&_mutex);
	kkk++;
	list_add_tail(&tx->txs, &txlist);
	pthread_mutex_unlock(&_mutex);

	return tx;
}

int
txn_log_op(struct txn *tx, int npg, size_t len, char *fmt1, char *fmt2, ...)
{
	struct pgmop *mop;
	struct pgdop *dop;
	void *p, *d;
	va_list valist;
	size_t dop_size;
	size_t mop_size;
	int i, n;

	dop_size = sizeof(struct pgdop) + npg * sizeof(struct pgdop_info) + len;
	dop_size = (dop_size + 1) & ~1UL;
	mop_size = sizeof (struct pgmop) + npg * sizeof (struct pgmop_info);
	if (!(mop = malloc(mop_size + dop_size)))
		return -ENOMEM;

	va_start(valist, fmt2);

	dop = ((void *) mop) + mop_size;
	dop->txid = tx->id;
	dop->npg = npg; 
	for (i = 0; i < npg; i++) {
		uint64_t *lsnp;
		uint64_t  pgno;
		struct list_head *head;

		pgno = va_arg(valist, uint64_t);
		lsnp = va_arg(valist, uint64_t *);
		head = va_arg(valist, void *);
		dop->pginfo[i].pgno = pgno;
		dop->pginfo[i].prev_lsn = *lsnp;
		*lsnp = dop->pginfo[i].lsn = txn_get_next_lsn();

		list_add_tail(&mop->pginfo[i].pgops, head);
		mop->pginfo[i].mop = mop;
	}
	p = (void *) &dop->pginfo[i];
redo:
	while (fmt1 && fmt1[0]) {
		switch (fmt1[0]) {
	    	case 'c':
			*(char *) p = va_arg(valist, int);
			p += 1;
			break;
		case 'w':
			*(uint32_t *) p = va_arg(valist, int);
			p += 4;
			break;
		case 'p':
			*(uint64_t *) p = va_arg(valist, uint64_t);
			p += 8;
			break;
		case 'd':
			d = va_arg(valist, char *);
			n = va_arg(valist, int); 
			memcpy(p, d, n);
			p += n;
			break;
		default:
			break;
		}
		fmt1++;
	}
	if (fmt2) {
		va_end(valist);
		valist[0] =  (*(va_list *)va_arg(valist, va_list *))[0];
		fmt1 = fmt2;
		fmt2 = NULL;
		goto redo;
	} else {
		// va_end(valist);
	}
	assert (p <= (((void *) mop) + mop_size + dop_size));
	mop->dop = dop;
	mop->size = dop_size;
	mop->tx = tx;

	pthread_mutex_lock(&txlock);
	list_add_tail(&mop->lgops, &gbl_ops);
	tx->npg_total += npg;
	pthread_mutex_unlock(&txlock);

	list_add_tail(&mop->txops, &tx->mops);
	return 0;
}

#if 0
#define HASHSIZE	100
#define	HASHKEY(pgno)	(pgno % HASHSIZE)
static struct hlist_head	hash_table[HASHSIZE];
static pthread_mutex_t hlock = PTHREAD_MUTEX_INITIALIZER;

static struct txn *
__get_txn(uint64_t id)
{
	struct hlist_head *head;
	struct txn *tx;

	pthread_mutex_lock(&hlock);
	head = &hash_table[HASHKEY(pgno)];
	hlist_for_each_entry(tx, head, hq) {
		if (tx->id == id) {
			pthread_mutex_unlock(&hlock);
			return tx;
		}
	}
	if (!(tx = malloc(sizeof (struct txn)))) {
		pthread_mutex_unlock(&hlock);
		return ERR_PTR(-ENOMEM);
	}
	tx->id = id;
	INIT_LIST_HEAD(&tx->mops);
	tx->ncommited = 0;
	tx->ntotal = 0;
	tx->omp = NULL;
	tx->pm = NULL;
	hlist_add_head(&tx->hq, head);
	pthread_mutex_unlock(&hlock);
	return tx;
}
#endif

static int
__tx_ops_flush()
{
	lm_log_t *lg;
	struct pgmop *mop;
	struct list_head list;

	INIT_LIST_HEAD(&list);

	pthread_mutex_lock(&txlock);
	list_splice(&gbl_ops, &list);
	INIT_LIST_HEAD(&gbl_ops);
	pthread_mutex_unlock(&txlock);

	if (list_empty(&list))
		return 0;

	list_for_each_entry(mop, &list, lgops) {
		if (IS_ERR(lg = lm_write(mop->dop, mop->size))) {
			return PTR_ERR(lg);
		}
		assert(lg);
		mop->lg = lg;
	}
	return 0;
}

static void
__end_tx(struct txn *tx)
{
	struct pgmop *mop, *tmp;

	list_for_each_entry_safe(mop, tmp, &tx->mops, txops) {
		list_del(&mop->txops);
		log_put(mop->lg);
		(g_tx_commit_cb)(((void *)(mop->dop + 1)) +
		    (sizeof (struct pgdop_info) * mop->dop->npg));
		free(mop);
	}
	log_put(tx->mop->lg);
	free(tx->mop);
	tx->mop = NULL;
	txn_free(tx);
}

static void __mop_mark_commited(struct pgmop *mop)
{
	struct txn *tx = mop->tx;

	pthread_mutex_lock(&txlock);
	if (++tx->npg_cmted == tx->npg_total && tx->mop) {
		pthread_mutex_unlock(&txlock);
		__end_tx(tx);
		return;
	}
	pthread_mutex_unlock(&txlock);
}

static void
__pg_mark_commited(struct list_head *mops)
{
	struct pgmop_info *pgi, *t_pgi;
	struct pgmop *mop;

	list_for_each_entry_safe(pgi, t_pgi, mops, pgops) {
		mop = pgi->mop;

		list_del(&pgi->pgops);
		__mop_mark_commited(mop);
	}
}

static pthread_mutex_t iolock = PTHREAD_MUTEX_INITIALIZER;

int
txn_commit(struct txn *tx, bool sys)
{
	lm_log_t *lg;
	struct tx_commit_rec *cr;
	int ret;
	struct pgmop *mop, *tmp;

	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct tx_commit_rec))))
		return -ENOMEM;

	mop->dop = (struct pgdop *)(mop + 1);
	cr = (struct tx_commit_rec *) mop->dop;
	cr->type = PGOP_COMMIT_TXN;
	cr->txid = tx->id;

	mop->size = sizeof (struct tx_commit_rec);
	
	pthread_mutex_lock(&iolock);
	if ((ret = __tx_ops_flush())) {
		pthread_mutex_unlock(&iolock);
		return ret;
	}

	assert((sizeof(struct tx_commit_rec) % 2) == 0);
	if (IS_ERR(lg = lm_write(cr, sizeof(struct tx_commit_rec)))) {
		pthread_mutex_unlock(&iolock);
		return PTR_ERR(lg);
	}
	if ((ret = lm_commit())) {
		pthread_mutex_unlock(&iolock);
		return ret;
	}
	pthread_mutex_unlock(&iolock);

	mop->lg = lg;	
	pthread_mutex_lock(&txlock);
	tx->mop = mop;
	if (tx->npg_cmted == tx->npg_total) {
		pthread_mutex_unlock(&txlock);
		__end_tx(tx);
		return ret;
	}
	pthread_mutex_unlock(&txlock);
	return ret;
}

int
txn_log_page(uint64_t pgno, void *dp, size_t len)
{
	lm_log_t *lg;
	struct iovec iov[2];
	struct tx_commit_rec *cr;
	struct pgmop *mop;
	int ret;

	pthread_mutex_lock(&iolock);
	if ((ret = __tx_ops_flush())) {
		pthread_mutex_unlock(&iolock);
		return ret;
	}

	if ((ret = lm_commit())) {
		pthread_mutex_unlock(&iolock);
		return ret;
	}
	pthread_mutex_unlock(&iolock);
	return ret;

#if 0
	if (!(mop = malloc(sizeof (struct pgmop) +
	    sizeof (struct tx_commit_rec))))
		return -ENOMEM;

	cr = mop->dop = (struct pgdop *) (mop + 1);
	mop->size = sizeof (struct tx_commit_rec);

	cr->type = PGOP_COMMIT_PAGE;
	cr->pgno = pgno;

	iov[0].iov_base = cr;
	iov[0].iov_len = sizeof (struct tx_commit_rec);

	iov[1].iov_base = dp;
	iov[1].iov_len = len;

	assert(((len + sizeof(struct tx_commit_rec)) % 2) == 0);
	if (IS_ERR(lg = lm_writev(iov, 2, len + sizeof(struct tx_commit_rec))))
		return PTR_ERR(lg);
	mop->lg = lg;
	if ((ret = lm_commit()))
		return ret;
	pg->mop = mop;
	__pg_mark_commited(pg);
	return 0;
#endif
}

int
txn_commit_page(struct list_head *head, int err)
{
	struct pgmop *mop;

	__pg_mark_commited(head);
	/*
	if (pg->mop) {
		log_put(pg->mop->lg);
		free(pg->mop);
		pg->mop = NULL;
	}
	*/
	return err;
}

int
tx_register_commit_cb(tx_commit_cb_t cb)
{
	g_tx_commit_cb = cb;
}

void
tx_system_exit(void)
{
	return;
}

int
tx_system_init(int fd)
{
	int ret;
#if 0
	int i;

	for (i = 0; i < HASHSIZE; i++)
		INIT_HLIST_HEAD(&hash_table[i]);
#endif
	INIT_LIST_HEAD(&gbl_ops);
	INIT_LIST_HEAD(&txlist);
	if ((ret = rm_recover()))
		return ret;
	return 0;
}
