#include "pm_int.h"

int db_fd;
 
static void
__page_free(pg_mgr_t *pm, struct page *pg)
{
	printf("releasing:%ld\n", pg->pgno);
	pm->exit_mpage(PG2MPG(pg));
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
	pg->stale = false;
	pg->pgno = pgno;
	pg->count = 0;
	pg->size = size;
	pthread_mutex_init(&pg->iolock, NULL);
	pthread_rwlock_init(&pg->lock, NULL);
	pg->readers = pg->writers = 0;
	pg->dp_mem = NULL;
	INIT_HLIST_NODE(&pg->hq);
	pg->dp = malloc(size);
	if (!pg->dp) 
		return (-ENOMEM);
	return pm->init_mpage(PG2MPG(pg));
}

static void
__page_put_locked(pg_mgr_t *pm, struct page *pg)
{
	assert(pg->count > 0);
	if (--pg->count == 0) {
		if (pg->stale) {
			pthread_mutex_unlock(&pm->lock);
			__page_free(pm, pg);
			pthread_mutex_lock(&pm->lock);
			return;
		}
		assert(pg->size == PAGE_SIZE);
		switch (pg->state) {
		case NEW:
		case UPTODATE:
			list_add_tail(&pg->q, &pm->clean_lru_pages);
			if (pm->nlru++ == 100) {
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
			list_add_tail(&pg->q, &pm->dirty_lru_pages);
			pthread_cond_signal(&pm->cond);
			break;
		case WRITING:
		case COWED:
		case COWED_DIRTY:
		case READING:
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
		pg->state = DIRTY;
		break;
	case COWED:
		pg->state = COWED_DIRTY;	
		break;
	case DIRTY:
	case COWED_DIRTY:
		break;
	case READING:
	case WRITING:
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
	__delete_locked_htab(pm, pg);
	pg->stale = true;
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
		if (b == PAGE_SIZE)
			pg->state = UPTODATE;
		else {
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
__page_wrlock(pg_mgr_t *pm, struct page *pg)
{
	pthread_rwlock_wrlock(&pg->lock);
	assert(pg->writers == 0);
	pg->writers++;

	__page_cow(pm, pg);
}

static void
__page_rdlock(pg_mgr_t *pm, struct page *pg)
{
	pthread_rwlock_rdlock(&pg->lock);
	assert(pg->writers == 0);
	__sync_fetch_and_add(&pg->readers, 1);
}

static void
__page_unlock(pg_mgr_t *pm, struct page *pg)
{
	if (pg->writers) {
		pg->writers--;
		assert(pg->writers == 0);
	} else {
		assert(pg->readers);
		__sync_fetch_and_sub(&pg->readers, 1);
		assert(pg->readers >= 0);
	}
	pthread_rwlock_unlock(&pg->lock);
}

static int
__page_write(pg_mgr_t *pm, struct page *pg)
{
	void *dp;
	ssize_t b;
	int err;

	assert(!pg->stale);
	switch (pg->state) {
	case DIRTY:
		pg->state = WRITING;
		dp = pg->dp;
		break;
	case NEW:
	case UPTODATE:
	case READING:
	case WRITING:
	case COWED:
	case COWED_DIRTY:
	default:
		assert(0);
		break;
	}
	pthread_mutex_unlock(&pm->lock);

	printf("Writing:%ld\n", pg->pgno);
	b = pwrite(db_fd, dp, PAGE_SIZE, pg->pgno << PAGE_SHFT);
	err = (b == PAGE_SIZE) ? 0 : -EIO;
    
	pthread_mutex_lock(&pm->lock);
	switch (pg->state) {
	case NEW:
	case DIRTY:
	case UPTODATE:
	case READING:
		assert (0);
		break;
	case COWED:
		free(dp);
		/* fall through */
	case WRITING:
		if (!err) 
			pg->state = UPTODATE;
		else 
			pg->state = DIRTY;
		break;
	case COWED_DIRTY:
		free(dp);
		pg->state = DIRTY;
		break;
	default:
		assert(0);
		break;
	}
	return err;
}

static struct page *
__page_new(pg_mgr_t *pm, pgno_t pgno, size_t size)
{
	int err;
	struct page *pg;

	if (!(pg = malloc(SIZEOF_PAGE(pm))))
		return NULL;
	if ((err = __page_init(pm, pg, pgno, size))) {
		__page_free(pm, pg);
		return NULL;
	}
	return pg;
}

static struct mpage *
__page_get(pg_mgr_t *pm, uint64_t pgno, size_t size, bool nowait, bool noread)
{
	struct page *new_pg = NULL;
	struct page *pg;
	int err;

	if (!(pg = __lookup_htab(pm, pgno))) {
		if (!(new_pg = __page_new(pm, pgno, size))) 
			return ERR_PTR(-ENOMEM);
		pg = __lookup_and_insert_htab(pm, new_pg);
	} 

	pthread_mutex_lock(&pm->lock);
	switch (pg->state) {
	case NEW:
		if (noread)
			break;
		/* fall through */
	case READING:
		if (nowait) {
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
		printf("%ld in GET writing\n", pgno);
		if (!pg->dp_mem && !(pg->dp_mem = malloc(size))) {
			__page_put_locked(pm, pg);
			return ERR_PTR(-ENOMEM);
		}
		break;
	case UPTODATE:
	case DIRTY:
	case COWED:
	case COWED_DIRTY:
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

void
pm_page_wrlock(pg_mgr_t *pm, struct mpage *mp)
{
	__page_wrlock(pm, MPG2PG(mp));
}

void 
pm_page_unlock(pg_mgr_t *pm, struct mpage *mp)
{
	__page_unlock(pm, MPG2PG(mp));
}

static void * syncer(void *arg)
{
	pg_mgr_t *pm = (pg_mgr_t *) arg;
	struct page *pg;

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
		list_del(&pg->q);
		pg->count++;

		__page_write(pm, pg);
		__page_put_locked(pm, pg);
	}
	pthread_mutex_unlock(&pm->lock);
	return NULL;
}

pg_mgr_t *
pm_alloc(size_t mp_sz, init_mpage_t init_cb, exit_mpage_t exit_cb)
{
	pg_mgr_t *pm;
	int i, err;

	if (!(pm = calloc(1, sizeof (pg_mgr_t))))
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&pm->dirty_lru_pages);
	INIT_LIST_HEAD(&pm->clean_lru_pages);
	for (i = 0; i < HASHSIZE; i++)
		INIT_HLIST_HEAD(&pm->hash_table[i]);
	pthread_mutex_init(&pm->lock, NULL);
	pthread_cond_init(&pm->cond, NULL);
	pm->init_mpage = init_cb;
	pm->exit_mpage = exit_cb;
	pm->mp_sz = mp_sz;
	pm->active = true;

	if ((err = pthread_create(&pm->syncer, NULL, syncer, (void *) pm))) {
		free(pm);
		return ERR_PTR(err);
	}
	return pm;
}

void
pm_free(pg_mgr_t *pm)
{
	pm->active = false;
	pthread_cond_signal(&pm->cond);
	pthread_join(pm->syncer, NULL);
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

	db_fd = fd;    
	return 0;
}
