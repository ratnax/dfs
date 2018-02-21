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
#define	DP_HDRLEN 	sizeof(struct dpage)
#define	DP_NXTINDX(p)	(((p)->lower - DP_HDRLEN) / sizeof(indx_t))


struct metadata {
	uint64_t root_pgno;
};

typedef int lock_type_t;

/* in-mem btree page */
struct mpage {
	pgno_t	pgno;
	pthread_rwlock_t lock;
#define MP_DIRTY 		0x1
#define MP_SPLITTING 	0X2
#define MP_LEFTMOST 	0x4
#define MP_RIGHTMOST 	0x8
#define MP_BIGPAGE 		0x10
#define MP_METADATA		0x20
#define MP_DELETING		0x40
#define MP_DELETED		0x80
#define MP_INSPLQ 		0x100
#define MP_INDELQ 		0x200
	bool leftmost;

	uint32_t flags;
	uint32_t npg;
	int32_t count;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	TAILQ_ENTRY(mpage) spl_entries;
	TAILQ_ENTRY(mpage) del_entries;
	union {
		struct dpage *dp;
		struct metadata *md;
		void *p;
	};
};

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

#define PAGE_LOCK_SHARED 1
#define PAGE_LOCK_EXCL   2

#define P_MDPGNO 0
#define DP_MAX_KSIZE 256
#define DP_MAX_DSIZE 256


#define PAGE_SHFT (9)
#define PAGE_SIZE (1U<<PAGE_SHFT)
#define PAGE_MASK (PAGE_SIZE - 1)





