#include "pm_int.h"

int db_fd;
static struct page *pages[MAX_PAGES];
static pthread_mutex_t page_lock = PTHREAD_MUTEX_INITIALIZER;
 
static int
__page_init(pg_mgr_t *pm, struct page *pg, uint64_t pgno, uint32_t size)
{
	pg->pgno = pgno;
	pg->count = 0;
	pg->size = size;
	pthread_mutex_init(&pg->iolock, NULL);
	pthread_rwlock_init(&pg->lock, NULL);
	pg->readers = pg->writers = 0;
	pg->mark = 0;
	pg->uptodate = false;
	pg->dp = malloc(size);
	if (!pg->dp) 
		return (-ENOMEM);
	return pm->init_mpage(PG2MPG(pg));
}

static void
__page_free(pg_mgr_t *pm, struct page *pg)
{
	pm->exit_mpage(PG2MPG(pg));
	if (pg->dp)
		free(pg->dp); 
	free(pg);
}

static void
__page_put(pg_mgr_t *pm, struct page *pg)
{
	pthread_mutex_lock(&page_lock);
	if (--pg->count == 0) {
		if (pages[pg->pgno] == NULL) 
			__page_free(pm, pg);
//		pages[pg->pgno] = NULL;
//		__page_free(pg);
	}
	pthread_mutex_unlock(&page_lock);
}

void
pm_page_delete(pg_mgr_t *pm, struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);

	pthread_mutex_lock(&page_lock);
	pages[pg->pgno] = NULL;
	pthread_mutex_unlock(&page_lock);
}

void
pm_page_put(pg_mgr_t *pm,  struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);
	__page_put(pm, pg);
}

static int
__page_read(struct page *pg)
{  
	ssize_t bread;

	pthread_mutex_lock(&pg->iolock);
	if (!pg->uptodate) {
		bread = pread(db_fd, pg->dp, PAGE_SIZE, pg->pgno << PAGE_SHFT);
		if (bread == PAGE_SIZE)
			pg->uptodate = true;
	}
	pthread_mutex_unlock(&pg->iolock);
	return (pg->uptodate ? 0 : -EIO);
}

static struct mpage *
__page_get(pg_mgr_t *pm, uint64_t pgno, size_t size, bool nowait, bool noread)
{
	struct page *pg;
	int err;

	pthread_mutex_lock(&page_lock);
	if (!(pg = pages[pgno])) { 
		pthread_mutex_unlock(&page_lock);
		pg = malloc(SIZEOF_PAGE(pm));
		if (!pg)
			return (ERR_PTR(-ENOMEM));
		if ((err = __page_init(pm, pg, pgno, size))) {
			__page_free(pm, pg);
			return (ERR_PTR(err));
		}
		pthread_mutex_lock(&page_lock);
		if (!pages[pgno]) {
			pages[pgno] = pg;
		} else {
			__page_free(pm, pg);
			pg = pages[pgno];
		}	
	}
	pg->count++;
	pthread_mutex_unlock(&page_lock);

	if (noread) 
		pg->uptodate = true;
	if (pg->uptodate)
		return PG2MPG(pg);
	if (nowait) 
		return (ERR_PTR(-EAGAIN));
	if (!(err = __page_read(pg)))
		return PG2MPG(pg);
	__page_put(pm, pg);
	return (ERR_PTR(err));
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
	struct page *pg = MPG2PG(mp);

	pthread_rwlock_rdlock(&pg->lock);
	assert(pg->writers == 0);
	__sync_fetch_and_add(&pg->readers, 1);
}

void
pm_page_wrlock(pg_mgr_t *pm, struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);

	pthread_rwlock_wrlock(&pg->lock);
	assert(pg->writers == 0);
	pg->writers++;
}

void 
pm_page_unlock(pg_mgr_t *pm, struct mpage *mp)
{
	struct page *pg = MPG2PG(mp);
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

int
pm_system_init(int fd)
{
	db_fd = fd;    
	return 0;
}

pg_mgr_t *
pm_alloc(size_t mp_sz, init_mpage_t init_cb, exit_mpage_t exit_cb)
{
	pg_mgr_t *pm;

	if (!(pm = calloc(1, sizeof (pg_mgr_t))))
		return ERR_PTR(-ENOMEM);
	pm->init_mpage = init_cb;
	pm->exit_mpage = exit_cb;
	pm->mp_sz = mp_sz;
	return pm;
}

void
pm_free(pg_mgr_t *pm)
{
	free(pm);
}
