#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/queue.h>

#define printf(fmt, ...) 

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

typedef uint64_t 	pgno_t;
typedef uint16_t	indx_t;

#define BT_MDPGNO 	(0)

/* Key/data structure -- a Data-Base Thang. */
typedef struct {
	void	*data;
	size_t	 size;
} DBT;


struct dpage {
	uint32_t lsn;    	
#define	DP_BINTERNAL 	0x01
#define	DP_BLEAF 		0x02
#define DP_TYPE			0x03
	uint32_t flags;

	indx_t	lower;			/* lower bound of free space on page */
	indx_t	upper;			/* upper bound of free space on page */
	indx_t	linp[0];		/* indx_t-aligned VAR. LENGTH DATA */
};

/* First and next index. */
#define	DP_HDRLEN 		sizeof(struct dpage)
#define	DP_NXTINDX(p)	(((p)->lower - DP_HDRLEN) / sizeof(indx_t))

struct metadata {
	uint64_t root_pgno;
};

typedef enum { PAGE_LOCK_SHARED, PAGE_LOCK_EXCL } lock_type_t;
typedef enum { 
	MP_STATE_NORMAL,
	MP_STATE_INREORGQ,
	MP_STATE_PREREORG,
	MP_STATE_REORGING,
	MP_STATE_DELETED
} mp_state_t;

/* in-mem btree page */
struct mpage {
	pgno_t	pgno;
	pthread_rwlock_t lock;
	bool leftmost;
	mp_state_t state;
#define MP_FLAG_METADATA 0x1
	uint32_t flags;
	int writers;
	int readers;
	uint32_t npg;
	int32_t count;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	TAILQ_ENTRY(mpage) reorg_queue_entry;
	union {
		struct dpage *dp;
		struct metadata *md;
		void *p;
	};
};

#define MP_NORMAL(mp)		((mp)->state == MP_STATE_NORMAL)
#define MP_INREORGQ(mp)		((mp)->state == MP_STATE_INREORGQ)
#define MP_PREREORG(mp)		((mp)->state == MP_STATE_PREREORG)
#define MP_REORGING(mp)		((mp)->state == MP_STATE_REORGING)
#define MP_DELETED(mp)		((mp)->state == MP_STATE_DELETED)

#define MP_METADATA(mp)		((mp)->flags & MP_FLAG_METADATA)
#define MP_SET_METADATA(mp)	(mp)->flags |= MP_FLAG_METADATA

#define DP_UNUSED(dp)	((dp)->upper - (dp)->lower)
#define MP_ISFULL(mp)	((mp)->npg == 15 && DP_UNUSED((mp)->dp) < PAGE_SIZE)
#define MP_EXTENDED(mp)		((mp)->npg > 1)
#define MP_NEED_SPLIT(mp)	(MP_EXTENDED(mp))

typedef struct dinternal {
	uint64_t ksize:8;
	uint64_t pgno:56;
	uint8_t bytes[0];
} DINTERNAL;

#define	GETDINTERNAL(dp, indx) 						\
	((DINTERNAL *)((char *)(dp) + (dp)->linp[indx]))

#define NDINTERNAL(len)	(sizeof(DINTERNAL) + len)

/* For the btree leaf pages, the item is a key and data pair. */
typedef struct dleaf {
	uint8_t	ksize;
	uint8_t	dsize;
	uint8_t bytes[0];
} DLEAF;

/* Get the page's BLEAF structure at index indx. */
#define	GETDLEAF(dp, indx)										\
	((DLEAF *)((char *)(dp) + (dp)->linp[indx]))

#define NDLEAFDBT(ksize, dsize) 	(sizeof(DLEAF) + ksize + dsize)

/* Get the number of bytes in the entry. */
#define NDLEAF(p)	NDLEAFDBT((p)->ksize, (p)->dsize)


#define DP_ISEMPTY(dp) ((dp)->lower == DP_HDRLEN)
#define MP_ISEMPTY(mp) (DP_ISEMPTY((mp)->dp))

#define MP_ISLEAF(mp) 		((mp)->dp->flags & DP_BLEAF)
#define MP_ISINTERNAL(mp) 	((mp)->dp->flags & DP_BINTERNAL)

typedef struct BTREE_s {
	int (*bt_cmp)(const DBT *a, const DBT *b);
} BTREE;

#define MAX_ERRNO	4096
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

static inline void * ERR_PTR(long error)
{
		return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
		return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
		return IS_ERR_VALUE((unsigned long)ptr);
}

#define P_MDPGNO 0
#define DP_MAX_KSIZE 256
#define DP_MAX_DSIZE 256


#define PAGE_SHFT (9)
#define PAGE_SIZE (1U<<PAGE_SHFT)
#define PAGE_MASK (PAGE_SIZE - 1)


extern struct mpage *bt_page_get_nowait(uint64_t pgno);
extern struct mpage *bt_page_get(uint64_t pgno);
extern void bt_page_lock(struct mpage *mp, lock_type_t type);
extern void bt_page_unlock(struct mpage *mp);
extern struct mpage *bt_page_new(int npg);
extern void bt_page_put(struct mpage *mp);
extern void bt_page_ref(struct mpage *mp);
extern int bt_page_init(void);
