#ifndef __PG_H__
#define __PG_H__

#include "global.h"
#include "pm_ext.h"

#define MAX_PAGES   (TOTAL_SPACE >> PAGE_SHFT)

struct dpage {
	DPAGE_STRUCT_HDR;
};

struct page {
	int32_t count;

	pthread_mutex_t iolock;
	pthread_rwlock_t lock;
	int writers;
	int readers;
	bool mark;
	bool uptodate;

	PAGE_STRUCT_TLR;
};

#define MPG2PG(mp)	((void *) (mp) - offsetof(struct page, pgno))
#define PG2MPG(pg)	((struct mpage *) &pg->pgno) 
#define SIZEOF_PAGE(pm)	(offsetof(struct page, pgno) + (pm)->mp_sz)

struct page_mgr {
    init_mpage_t init_mpage;
    exit_mpage_t exit_mpage;
    size_t mp_sz;
};
#endif 
