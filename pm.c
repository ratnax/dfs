#include "pm_int.h"

int db_fd;

static pg_mgr_t *pm_mgrs[4]; 
 
static void
__page_free(pg_mgr_t *pm, struct page *pg)
{
	struct pgmop *mop;
	printf("releasing:%ld %s\n", pg->pgno, pg->state == DELETED ?
		"yes":"no");

	txn_commit_page(&pg->mops);
	assert(list_empty(&pg->mops));
	pm->exit_mpage(PG2MPG(pg), pg->state == DELETED);
	if (pg->dp)
		free(pg->dp); 
	if (pg->dp_mem)
		free(pg->dp_mem); 
	free(pg);
}

static void
__insert_locked_htab(pg_mgr_t *pm, struct page *pg)
{
	hlist_add_head(&pg->hq, &pm->hash_table[HASHKEY(pg->pgno)]);
}

static void
__insert_htab(pg_mgr_t *pm, struct page *pg)
{
	pthread_mutex_lock(&pm->lock);
	__insert_locked_htab(pm, pg);
	pthread_mutex_unlock(&pm->lock);
}

static struct page *
__lookup_locked_htab(pg_mgr_t *pm, pgno_t pgno)
{
	struct hlist_head *head;
	struct page *pg;

	head = &pm->hash_table[HASHKEY(pgno)];
	hlist_for_each_entry(pg, head, hq) {
		if (pg->pgno == pgno) {
			if (pg->count == 0) {
				if (pg->state == NEW || pg->state == UPTODATE)
					pm->nlru--;
				list_del(&pg->q);	
			}
			pg->count++;
			return pg;
		}
	}
	return NULL;
}

static struct page *
__lookup_and_insert_htab(pg_mgr_t *pm, struct page *new_pg)
{
	struct page *pg;
	pgno_t pgno = new_pg->pgno;

	pthread_mutex_lock(&pm->lock);
	pg = __lookup_locked_htab(pm, pgno);
	if (!pg) { 
		new_pg->count++;
		__insert_locked_htab(pm, new_pg);
		pthread_mutex_unlock(&pm->lock);
		return new_pg;
	}
	pthread_mutex_unlock(&pm->lock);
	__page_free(pm, new_pg);
	return pg;
}

static struct page *
__lookup_htab(pg_mgr_t *pm, pgno_t pgno)
{
	struct page *pg;

	pthread_mutex_lock(&pm->lock);
	pg = __lookup_locked_htab(pm, pgno);
	pthread_mutex_unlock(&pm->lock);
	return pg;
}

static void
__delete_locked_htab(pg_mgr_t *pm, struct page *pg)
{
	hlist_del(&pg->hq);
}

static void
__delete_htab(pg_mgr_t *pm, struct page *pg)
{
	pthread_mutex_lock(&pm->lock);
	__delete_locked_htab(pm, pg);
	pthread_mutex_unlock(&pm->lock);
}

static int
__page_init(pg_mgr_t *pm, struct page *pg, uint64_t pgno, uint32_t size)
{
	pg->state = NEW;
	pg->pgno = pgno;
	pg->count = 0;
	pg->size = size;
	pg->mop = NULL;
	pg->tx = NULL;
	pthread_mutex_init(&pg->iolock, NULL);
	pthread_rwlock_init(&pg->lock, NULL);
	pg->readers = pg->writers = 0;
	pg->dp_mem = NULL;
	INIT_HLIST_NODE(&pg->hq);
	INIT_LIST_HEAD(&pg->mops);
	if (!(pg->dp = malloc(size)))
		return (-ENOMEM);
	return pm->init_mpage(PG2MPG(pg));
}

static void
__page_put_locked(pg_mgr_t *pm, struct page *pg)
{
	assert(pg->count > 0);
	if (--pg->count == 0) {
		switch (pg->state) {
		case NEW:
		case DELETED:
			__delete_locked_htab(pm, pg);
			pthread_mutex_unlock(&pm->lock);
			__page_free(pm, pg);
			pthread_mutex_lock(&pm->lock);
			break;
		case UPTODATE:
			assert(pg->size == PAGE_SIZE);
			list_add_tail(&pg->q, &pm->clean_lru_pages);
			if (pm->nlru++ == pm->max_nlru) {
				pg = list_first_entry(&pm->clean_lru_pages,
				    struct page, q);

				__delete_locked_htab(pm, pg);
				list_del(&pg->q);
				pm->nlru--;
				pthread_mutex_unlock(&pm->lock);
				__page_free(pm, pg);
				pthread_mutex_lock(&pm->lock);
			}
			break;
		case DIRTY:
			assert(pg->size == PAGE_SIZE);
			list_add_tail(&pg->q, &pm->dirty_lru_pages);
			pthread_cond_signal(&pm->cond);
			break;
		case WRITING:
		case READING:
		case COWED:
		default:
			assert(0);
		}
	}
}

static void
__page_put(pg_mgr_t *pm, struct page *pg)
{
	pthread_mutex_lock(&pm->lock);
	__page_put_locked(pm, pg);
	pthread_mutex_unlock(&pm->lock);
}

void
pm_page_mark_dirty(pg_mgr_t *pm, struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);

	assert(pg->count);
	pthread_mutex_lock(&pm->lock);
	switch (pg->state) {
	case NEW:
	case UPTODATE:
	case DELETED:
	case COWED:
		pg->state = DIRTY;
		break;
	case DIRTY:
		break;
	case WRITING:
	case READING:
	default:
		assert(0);
	}
	pthread_mutex_unlock(&pm->lock);
}

void
pm_page_delete(pg_mgr_t *pm, struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);

	pthread_mutex_lock(&pm->lock);
	switch (pg->state) {
	case NEW:
	case UPTODATE:
	case DIRTY:
	case COWED:
		pg->state = DELETED;
	case DELETED:
		break;
	case READING:
	case WRITING:
	default:
		assert(0);
	}
	pthread_mutex_unlock(&pm->lock);
}

void
pm_page_put(pg_mgr_t *pm,  struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);
	__page_put(pm, pg);
}

static int
__page_read(pg_mgr_t *pm, struct page *pg)
{
	ssize_t b;
	int err = 0;

	pthread_mutex_lock(&pg->iolock);
	pthread_mutex_lock(&pm->lock);
	if (pg->state == NEW) {
		pg->state = READING;
		pthread_mutex_unlock(&pm->lock);
		printf("reading:%ld\n", pg->pgno);
		b = pread(db_fd, pg->dp, PAGE_SIZE, pg->pgno << PAGE_SHFT);
		pthread_mutex_lock(&pm->lock);
		if (b == PAGE_SIZE) {
			pm->read_mpage(PG2MPG(pg));
			pg->state = UPTODATE;
		} else {
			assert(0);
			pg->state = NEW;
			err = -EIO;
		}
	}
	pthread_mutex_unlock(&pm->lock);
	pthread_mutex_unlock(&pg->iolock);
	return err;
}

static void
__page_cow(pg_mgr_t *pm, struct page *pg)
{
	struct dpage *dp = pg->dp_mem;

	assert(pg->state != READING);

	if (pg->state != WRITING)
		return;

	assert(dp);
	pthread_mutex_lock(&pm->lock);
	if (pg->state == WRITING) {
		assert(pg->size == PAGE_SIZE);
		memcpy(dp, pg->dp, pg->size);
		pg->dp = dp;
		pg->dp_mem = NULL;
		pg->state = COWED;
		printf("%ld COWED\n", pg->pgno);
	}
	pthread_mutex_unlock(&pm->lock);
}	

static void
__page_wrlock(pg_mgr_t *pm, struct page *pg, bool cow)
{
	pthread_rwlock_wrlock(&pg->lock);
	assert(pg->writers == 0);
	pg->writers++;

	if (cow)
	    __page_cow(pm, pg);
}

static void
__page_rdlock(pg_mgr_t *pm, struct page *pg)
{
	pthread_rwlock_rdlock(&pg->lock);
	assert(pg->writers == 0);
	__sync_fetch_and_add(&pg->readers, 1);
}

static bool 
__page_unlock(pg_mgr_t *pm, struct page *pg)
{
	bool ret = false;
	if (pg->writers) {
		pg->writers--;
		ret = true;
		assert(pg->writers == 0);
	} else {
		assert(pg->readers);
		__sync_fetch_and_sub(&pg->readers, 1);
		assert(pg->readers >= 0);
	}
	pthread_rwlock_unlock(&pg->lock);
	return ret;
}

static int
__page_write(pg_mgr_t *pm, struct page *pg)
{
	struct list_head mops;
	struct dpage *dp;
	ssize_t b;
	int err;

	switch (pg->state) {
	case DIRTY:
		pg->state = WRITING;
		dp = pg->dp;
		INIT_LIST_HEAD(&mops);
		list_splice(&pg->mops, &mops);
		INIT_LIST_HEAD(&pg->mops);
		break;
	case NEW:
	case UPTODATE:
	case READING:
	case WRITING:
	case DELETED:
	case COWED:
	default:
		assert(0);
		break;
	}
	pthread_mutex_unlock(&pm->lock);

	err = txn_log_page(pg, dp, PAGE_SIZE);
	assert(!err);

	printf("Writing:%ld\n", pg->pgno);
	b = pwrite(db_fd, dp, PAGE_SIZE, pg->pgno << PAGE_SHFT);
	err = (b == PAGE_SIZE) ? 0 : -EIO;
    
	err = txn_commit_page(&mops, err);

	printf("done writing %ld %d\n", pg->pgno, err);
	pthread_mutex_lock(&pm->lock);
	if (pg->state == WRITING || pg->state == COWED) {
		if (!err) {
			pg->state = UPTODATE;
		} else {
			pg->state = DIRTY;
		}
	}
	if (pg->dp != dp)
		free(dp);
	return err;
}

static struct page *
__page_new(pg_mgr_t *pm, pgno_t pgno, size_t size, bool noread)
{
	int err;
	struct page *pg;

	if (!(pg = malloc(SIZEOF_PAGE(pm))))
		return NULL;
	if ((err = __page_init(pm, pg, pgno, size))) {
		__page_free(pm, pg);
		return NULL;
	}
	if (noread)
		pg->state = DELETED;
	return pg;
}

static struct mpage *
__page_get(pg_mgr_t *pm, uint64_t pgno, size_t size, bool nowait, bool noread)
{
	struct page *new_pg = NULL;
	struct page *pg;
	int err;

	if (!(pg = __lookup_htab(pm, pgno))) {
		if (!(new_pg = __page_new(pm, pgno, size, noread))) 
			return ERR_PTR(-ENOMEM);
		pg = __lookup_and_insert_htab(pm, new_pg);
	} 

	pthread_mutex_lock(&pm->lock);
	switch (pg->state) {
	case NEW:
		if (noread) {
			pg->state = DELETED;
			break;
		}
		/* fall through */
	case READING:
		assert(pg->size == PAGE_SIZE);
		if (nowait) {
			__page_put_locked(pm, pg);
			pthread_mutex_unlock(&pm->lock);
			return ERR_PTR(-EAGAIN);
		}
		while (pg->state == READING || pg->state == NEW) {
			pthread_mutex_unlock(&pm->lock);
	    		if ((err = __page_read(pm, pg))) {
				__page_put(pm, pg);
				return ERR_PTR(err);
			}
			pthread_mutex_lock(&pm->lock);
		}
		break;
	case WRITING:
		assert(pg->size == PAGE_SIZE);
		if (!pg->dp_mem && !(pg->dp_mem = malloc(size))) {
			__page_put_locked(pm, pg);
			pthread_mutex_unlock(&pm->lock);
			return ERR_PTR(-ENOMEM);
		}
		break;
	case COWED:
	case DELETED:
	case UPTODATE:
	case DIRTY:
		break;
	default:
		assert(0);
	}
	pthread_mutex_unlock(&pm->lock);
	return PG2MPG(pg);
}

struct mpage *
pm_page_get_new(pg_mgr_t *pm, pgno_t pgno, size_t size)
{
	return __page_get(pm, pgno, size, false, true);
}

struct mpage *
pm_page_get_nowait(pg_mgr_t *pm, pgno_t pgno)
{
	return __page_get(pm, pgno, PAGE_SIZE, true, false);
}

struct mpage *
pm_page_get(pg_mgr_t *pm, pgno_t pgno)
{
	return __page_get(pm, pgno, PAGE_SIZE, false, false);
}

void
pm_page_rdlock(pg_mgr_t *pm, struct mpage *mp)
{
	__page_rdlock(pm, MPG2PG(mp));
}

int
pm_page_wrlock(pg_mgr_t *pm, struct txn *tx, struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);
	int ret;

	if ((ret = txn_reserve(tx)))
		return ret;
	__page_wrlock(pm, pg, true);
	pg->tx = tx;
	return 0;
}

void
pm_page_wrlock_nocow(pg_mgr_t *pm, struct mpage *mp)
{
	__page_wrlock(pm, MPG2PG(mp), false);
}

void 
pm_page_unlock(pg_mgr_t *pm, struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);
	struct txn *tx = pg->tx;

	pg->tx = NULL;
	if (__page_unlock(pm, pg) && tx)
		txn_unreserve(tx);
}

static void *syncer(void *arg)
{
	pg_mgr_t *pm = (pg_mgr_t *) arg;
	struct page *pg;
	struct pgmop *mop;

	pthread_mutex_lock(&pm->lock);
	while (1) {
		while (list_empty(&pm->dirty_lru_pages) && pm->active)
			pthread_cond_wait(&pm->cond, &pm->lock);

		if (!list_empty(&pm->dirty_lru_pages)) {
			pg = list_first_entry(&pm->dirty_lru_pages,
			    struct page, q);
		} else  
			break;

		assert(pg->count == 0);
		assert(pg->size == PAGE_SIZE);
		assert(pg->state == DIRTY);
	    
		list_del(&pg->q);
		pg->count++;

		__page_write(pm, pg);
		__page_put_locked(pm, pg);
	}
	pthread_mutex_unlock(&pm->lock);
	return NULL;
}

static void
__tx_commit_cb(void *p)
{
	struct page *pg;
	pm_type_t type;
	int npg;
	uint64_t pgno;
	uint64_t lsn;

	type = *(unsigned char *) p;
	p += 1;
	npg = *(unsigned char *) p;
	p += 1;
	if (!npg) 
		return;
	pgno = *(uint64_t *) p;
	p += 8;
	lsn = *(uint64_t *) p;
	p += 8;

	pg = __lookup_htab(pm_mgrs[type], pgno);
	assert(pg);

	__page_put(pm_mgrs[type], pg);
	__page_put(pm_mgrs[type], pg);
	return;
}

struct pginfo {
	uint64_t pgno;
	uint64_t lsn;
};

struct pgop {
	uint8_t type;
	uint8_t npg;
	struct pginfo pgi[0];
} __attribute ((packed));

int
pm_txn_log_op(pg_mgr_t *pm, struct txn *tx, size_t len, int npg, int npg_topin,	    ...)
{
	int ret;
	struct  page *pg1;
	struct mpage *mp1;
	struct dpage *dp1;
	struct mpage *mp2;
	struct dpage *dp2;
	struct  page *pg2;
	struct mpage *mp3;
	struct dpage *dp3;
	struct  page *pg3;
	struct mpage *mp4;
	struct dpage *dp4;
	struct  page *pg4;

	struct mpage *pin_mp1;
	struct dpage *pin_dp1;
	struct  page *pin_pg1;

	struct pgop *p;
	size_t n;

	va_list valist;

	va_start(valist, npg_topin);
	switch (npg) {
	case 1:
		mp1 = va_arg(valist, struct mpage *);
		pg1 = MPG2PG(mp1);
		dp1 = pg1->dp;

		switch (npg_topin) {
		case 0:
			n = sizeof(struct pgop);
			p = txn_mem_alloc(tx, n);
			p->type = pm->type;
			p->npg = npg_topin;
			ret = txn_log_op(tx, len + n, 1, pg1->pgno, &dp1->lsn,
			    &pg1->mops);
			break;
		case 1:
			pin_mp1 = va_arg(valist, struct mpage *);
			pin_pg1 = MPG2PG(pin_mp1);
			pin_dp1 = pin_pg1->dp;

			pthread_mutex_lock(&pm->lock);
			pin_pg1->count++;
			pthread_mutex_unlock(&pm->lock);

			n = sizeof(struct pgop) + sizeof(struct pginfo);
			p = txn_mem_alloc(tx, n);
			p->type = pm->type;
			p->npg = npg_topin;
			p->pgi[0].pgno = pin_pg1->pgno;
			p->pgi[0].lsn = pin_dp1->lsn;

			ret = txn_log_op(tx, len + n, 1, pg1->pgno, &dp1->lsn, 
			    &pg1->mops);
			break;
		default:
			assert(0);
			break;
		}
		break;
	case 2:
		mp1 = va_arg(valist, struct mpage *);
		pg1 = MPG2PG(mp1);
		dp1 = pg1->dp;

		mp2 = va_arg(valist, struct mpage *);
		pg2 = MPG2PG(mp2);
		dp2 = pg2->dp;

		switch (npg_topin) {
		case 0:
			n = sizeof(struct pgop);
			p = txn_mem_alloc(tx, n);
			p->type = pm->type;
			p->npg = npg_topin;
			ret = txn_log_op(tx, len + n, 2, pg1->pgno, &dp1->lsn,
			    &pg1->mops, pg2->pgno, &dp2->lsn, &pg2->mops);
			break;
		case 1:    
			pin_mp1 = va_arg(valist, struct mpage *);
			pin_pg1 = MPG2PG(pin_mp1);
			pin_dp1 = pin_pg1->dp;

			pthread_mutex_lock(&pm->lock);
			pin_pg1->count++;
			pthread_mutex_unlock(&pm->lock);

			n = sizeof(struct pgop) + sizeof(struct pginfo);
			p = txn_mem_alloc(tx, n);
			p->type = pm->type;
			p->npg = npg_topin;
			p->pgi[0].pgno = pin_pg1->pgno;
			p->pgi[0].lsn = pin_dp1->lsn;
			ret = txn_log_op(tx, len + n, 2, pg1->pgno, &dp1->lsn,
			    &pg1->mops, pg2->pgno, &dp2->lsn, &pg2->mops);
			break;
		default:
			assert(0);
		}
		break;
	case 3:
		mp1 = va_arg(valist, struct mpage *);
		pg1 = MPG2PG(mp1);
		dp1 = pg1->dp;

		mp2 = va_arg(valist, struct mpage *);
		pg2 = MPG2PG(mp2);
		dp2 = pg2->dp;

		mp3 = va_arg(valist, struct mpage *);
		pg3 = MPG2PG(mp3);
		dp3 = pg3->dp;

		switch(npg_topin) {
		case 0:
    			n = sizeof(struct pgop);
			p = txn_mem_alloc(tx, n);
			p->type = pm->type;
			p->npg = npg_topin;
	    		ret = txn_log_op(tx, len + n, 3, pg1->pgno, &dp1->lsn,
			    &pg1->mops, pg2->pgno, &dp2->lsn, &pg2->mops,
			    pg3->pgno, &dp3->lsn, &pg3->mops);
			break;
		case 1:
			pin_mp1 = va_arg(valist, struct mpage *);
			pin_pg1 = MPG2PG(pin_mp1);
			pin_dp1 = pin_pg1->dp;

			pthread_mutex_lock(&pm->lock);
			pin_pg1->count++;
			pthread_mutex_unlock(&pm->lock);

			n = sizeof(struct pgop) + sizeof(struct pginfo);
			p = txn_mem_alloc(tx, n);
			p->type = pm->type;
			p->npg = npg_topin;
			p->pgi[0].pgno = pin_pg1->pgno;
			p->pgi[0].lsn = pin_dp1->lsn;
	    		ret = txn_log_op(tx, len + n, 3, pg1->pgno, &dp1->lsn,
			    &pg1->mops, pg2->pgno, &dp2->lsn, &pg2->mops,
			    pg3->pgno, &dp3->lsn, &pg3->mops);
			break;
		default:
			assert(0);
		}
		break;
	case 4:
		mp1 = va_arg(valist, struct mpage *);
		pg1 = MPG2PG(mp1);
		dp1 = pg1->dp;

		mp2 = va_arg(valist, struct mpage *);
		pg2 = MPG2PG(mp2);
		dp2 = pg2->dp;

		mp3 = va_arg(valist, struct mpage *);
		pg3 = MPG2PG(mp3);
		dp3 = pg3->dp;

		mp4 = va_arg(valist, struct mpage *);
		pg4 = MPG2PG(mp4);
		dp4 = pg4->dp;

		switch (npg_topin) {
		case 0:
    			n = sizeof(struct pgop);
			p = txn_mem_alloc(tx, n);
			p->type = pm->type;
			p->npg = npg_topin;
			ret = txn_log_op(tx, len + n, 4, pg1->pgno, &dp1->lsn,
			    &pg1->mops, pg2->pgno, &dp2->lsn, &pg2->mops,
			    pg3->pgno, &dp3->lsn, &pg3->mops, pg4->pgno,
			    &dp4->lsn, &pg4->mops);
			break;
		case 1:
			pin_mp1 = va_arg(valist, struct mpage *);
			pin_pg1 = MPG2PG(pin_mp1);
			pin_dp1 = pin_pg1->dp;

			pthread_mutex_lock(&pm->lock);
			pin_pg1->count++;
			pthread_mutex_unlock(&pm->lock);

			n = sizeof(struct pgop) + sizeof(struct pginfo);
			p = txn_mem_alloc(tx, n);
			p->type = pm->type;
			p->npg = npg_topin;
			p->pgi[0].pgno = pin_pg1->pgno;
			p->pgi[0].lsn = pin_dp1->lsn;

			ret = txn_log_op(tx, len + n, 4, pg1->pgno, &dp1->lsn,
			    &pg1->mops, pg2->pgno, &dp2->lsn, &pg2->mops,
			    pg3->pgno, &dp3->lsn, &pg3->mops, pg4->pgno,
			    &dp4->lsn, &pg4->mops);
			break;
		default:
			assert(0);
		}
		break;
	default:
		assert(0);
	}
	va_end(valist);
	return ret;
}

pg_mgr_t *
pm_alloc(pm_type_t type, size_t mp_sz, init_mpage_t init_cb,
    read_mpage_t read_cb, exit_mpage_t exit_cb, int max_nlru)
{
	pg_mgr_t *pm;
	int i, err;

	if (!(pm = malloc(sizeof (pg_mgr_t))))
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&pm->dirty_lru_pages);
	INIT_LIST_HEAD(&pm->clean_lru_pages);
	for (i = 0; i < HASHSIZE; i++)
		INIT_HLIST_HEAD(&pm->hash_table[i]);
	pthread_mutex_init(&pm->lock, NULL);
	pthread_cond_init(&pm->cond, NULL);
	pm->init_mpage = init_cb;
	pm->read_mpage = read_cb;
	pm->exit_mpage = exit_cb;
	pm->type = type;
	pm->max_nlru = max_nlru;
	pm->nlru = 0;
	pm->mp_sz = mp_sz;
	pm->active = true;

	if ((err = pthread_create(&pm->syncer, NULL, syncer, (void *) pm))) {
		free(pm);
		return ERR_PTR(err);
	}
	pm_mgrs[type] = pm;
	return pm;
}

void
pm_free(pg_mgr_t *pm)
{
	struct page *pg, *tmp;
	int i;

	pthread_mutex_lock(&pm->lock);
	pm->active = false;
	pthread_cond_signal(&pm->cond);
	pthread_mutex_unlock(&pm->lock);
	pthread_join(pm->syncer, NULL);

	list_for_each_entry_safe(pg, tmp, &pm->clean_lru_pages, q) {
		list_del(&pg->q);
		__delete_locked_htab(pm, pg);
		__page_free(pm, pg);
	}
	assert(list_empty(&pm->dirty_lru_pages));
	for (i = 0; i < HASHSIZE; i++) {
		assert(hlist_empty(&pm->hash_table[i]));
//		hlist_for_each_entry(pg, &pm->hash_table[i], hq) {
//			eprintf("%ld %d\n", pg->pgno, pg->count);
//		}
	}
	free(pm);
}

void
pm_system_exit(void)
{
}

int
pm_system_init(int fd)
{
	int i;

	tx_register_commit_cb(__tx_commit_cb);
	db_fd = fd;    
	return 0;
}
