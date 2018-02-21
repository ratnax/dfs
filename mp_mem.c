#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>


#include "mp_mem.h"

#define MP_MAXPAGES 1024000
static struct mpage mp_pages[MP_MAXPAGES];
static uint64_t page_map[MP_MAXPAGES / 64 + 1];
static pthread_mutex_t mutex;

struct mpage *bt_page_get_nowait(uint64_t pgno)
{
	assert(pgno < MP_MAXPAGES);

	pthread_mutex_lock(&mutex);
	mp_pages[pgno].count++;
	pthread_mutex_unlock(&mutex);

	assert(mp_pages[pgno].dp);
//	assert(!(mp_pages[pgno].flags & MP_DELETED));
	return &mp_pages[pgno];
}


struct mpage *bt_page_get(uint64_t pgno)
{
	struct mpage *mp = bt_page_get_nowait(pgno);
	assert(mp->dp);

	return mp;
}

void bt_page_lock(struct mpage *mp, lock_type_t type)
{
	if (type == PAGE_LOCK_SHARED) {
		pthread_rwlock_rdlock(&mp->lock);
		__sync_fetch_and_add(&mp->readers, 1);
	} else {
		pthread_rwlock_wrlock(&mp->lock);
		assert(mp->writers == 0);
		mp->writers++;
	}
}

void bt_page_unlock(struct mpage *mp)
{
	if (mp->writers) {
		mp->writers--;
		assert(mp->writers == 0);
	} else {
		assert(mp->readers);
		__sync_fetch_and_sub(&mp->readers, 1);
		assert(mp->readers >= 0);
	}
	pthread_rwlock_unlock(&mp->lock);
}


static __inline uint64_t __ffs64(uint64_t n)
{
	uint64_t lsb;
	asm("bsfq %1,%0" : "=r"(lsb) : "r"(n));
	return lsb;
}

pthread_mutex_t __m = PTHREAD_MUTEX_INITIALIZER;
int64_t __bt_page_new()
{
	int i, b;
	pthread_mutex_lock(&__m);
	for (i = 0; i < MP_MAXPAGES / 64; i++) {
		if (page_map[i] != ~0ULL) {
			b = __ffs64(~page_map[i]);
			page_map[i] |= (1ULL << b);
			printf("setting 0x%llx %d\n", page_map[i], i * 64 +b);
			pthread_mutex_unlock(&__m);
			return i * 64 + b;
		}
	}
	pthread_mutex_unlock(&__m);

	return -ENOSPC;
}

void __bt_page_free(uint64_t pgno)
{
	pthread_mutex_lock(&__m);
	page_map[pgno / 64] &= ~(1ULL << (pgno % 64));
	pthread_mutex_unlock(&__m);
	printf("clearing 0x%llx %llu\n", page_map[pgno/64], pgno);
}

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

struct mpage *bt_page_new(int npg)
{
	int64_t pgno = __bt_page_new();
	struct mpage *mp;
   
	assert(pgno >= 0);
	assert(pgno < MP_MAXPAGES);

	mp = &mp_pages[pgno];

	assert(!mp->dp);
	mp->dp = malloc(PAGE_SIZE * npg);
	if (!mp->dp) {
		__bt_page_free(pgno);
		return ERR_PTR(ENOSPC);
	}
	mp->npg = npg;
	mp->flags = 0;
	pthread_mutex_lock(&mutex);
	mp->count++;
	pthread_mutex_unlock(&mutex);
	return mp;
}

void bt_page_delete(struct mpage *mp)
{
	printf("mp deleted: %d\n", mp->pgno);
	mp->flags |= MP_DELETED;
}

void bt_page_put(struct mpage *mp)
{
	pthread_mutex_lock(&mutex);
	mp->count--;
	assert(mp->count >= 0);
	if (mp->count == 0) {
		pthread_mutex_unlock(&mutex);
		if (mp->flags & MP_DELETED) {
			if (mp->dp)
				free(mp->dp);
			mp->dp = NULL;
			__bt_page_free(mp->pgno);
		}
	} else {
		pthread_mutex_unlock(&mutex);
	}
}

void bt_page_ref(struct mpage *mp)
{
	pthread_mutex_lock(&mutex);
	mp->count++;
	pthread_mutex_unlock(&mutex);
}

int bt_page_init(void)
{
	struct mpage *mp;
	int i;

	for (i = 0; i < MP_MAXPAGES; i++) {
		mp = &mp_pages[i];	

		pthread_mutex_init(&mp->mutex, NULL);
		pthread_cond_init(&mp->cond, NULL);
		pthread_rwlock_init(&mp->lock, NULL);

		mp->flags = 0;
		mp->dp = NULL;

		mp->pgno = i;
	}		
}
