#ifndef __PG_H__
#define __PG_H__

#include "global.h"
#include "pm_ext.h"
#include "tx_ext.h"
#include "list.h"

#define MAX_PAGES   (TOTAL_SPACE >> PAGE_SHFT)

struct dpage {
	DPAGE_STRUCT_HDR;
};

typedef enum {
	NEW,
	READING,
	UPTODATE,
	DIRTY,
	WRITING,
	COWED,
	DELETED
} page_state_t;

struct page {
	int32_t			count;

	page_state_t		state;
	pthread_mutex_t		iolock;
	pthread_rwlock_t	lock;
	int			writers;
	int			readers;

	struct hlist_node	hq;		/* hash queue */
	struct list_head	q;		/* lru queue */
	struct list_head	mops;
	struct pgmop		*mop;
	struct txn		*tx;
	
	void			*dp_mem;
	PAGE_STRUCT_TLR;
};

#define MPG2PG(mp)	((void *) (mp) - offsetof(struct page, pgno))
#define PG2MPG(pg)	((struct mpage *) &pg->pgno) 
#define SIZEOF_PAGE(pm)	(offsetof(struct page, pgno) + (pm)->mp_sz)

struct page_mgr {
	struct list_head	dirty_lru_pages;
	struct list_head	clean_lru_pages;

	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	pthread_t		syncer;
	int			nlru;
	int			max_nlru;
#define	HASHSIZE		10240
#define	HASHKEY(pgno)		(pgno % HASHSIZE)
	struct hlist_head	hash_table[HASHSIZE];

	init_mpage_t		init_mpage;
	read_mpage_t		read_mpage;
	exit_mpage_t		exit_mpage;
	pm_type_t		type;
	size_t			mp_sz;
	bool			active;
};
#endif 
