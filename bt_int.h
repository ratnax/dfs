#ifndef __BT_INT_H__
#define __BT_INT_H__

#include "global.h"
#include "bm_ext.h"
#include "pm_ext.h"

typedef	uint16_t	indx_t;
typedef struct dbt {
	void	*data;
	size_t	 size;
} DBT;

#define	DP_METADATA	0x01
#define	DP_INTERNAL	0x02
#define	DP_LEAF		0x04
#define DP_TYPE		0x07

/* On-disk btree page */
struct dpage {
	DPAGE_STRUCT_HDR;
	union {
		/* Metadata */
		struct {
			pgno_t root_pgno;
		} __attribute__((packed));

		/* Leaf/Internal page. */
		struct {
			indx_t lower;/* lower bound of free space on page */
			indx_t upper;/* upper bound of free space on page */
			indx_t linp[0];	/* indx_t-aligned VAR. LENGTH DATA */
		} __attribute__((packed));
	} __attribute__((packed));
} __attribute__((packed));

/* First and next index. */
#define	DP_HDRLEN	offsetof(struct dpage, linp)
#define	DP_NXTINDX(dp)	(((dp)->lower - DP_HDRLEN) / sizeof (indx_t))

/* Btree page reorganisation state */
typedef enum {
	MP_STATE_INIT,
	MP_STATE_NORMAL,
	MP_STATE_INREORGQ,
	MP_STATE_PREREORG,
	MP_STATE_REORGING,
	MP_STATE_DELETED
} mp_state_t;

/* Btree page info in memory. */
struct mpage {
	MPAGE_STRUCT_HDR;
	mp_state_t state;
    	pthread_cond_t cond;
	pthread_mutex_t mutex;
	TAILQ_ENTRY(mpage) reorg_qentry;
};

#define MP_NORMAL(mp)		((mp)->state == MP_STATE_NORMAL)
#define MP_INREORGQ(mp)		((mp)->state == MP_STATE_INREORGQ)
#define MP_PREREORG(mp)		((mp)->state == MP_STATE_PREREORG)
#define MP_REORGING(mp)		((mp)->state == MP_STATE_REORGING)
#define MP_DELETED(mp)		((mp)->state == MP_STATE_DELETED)

#define DP_UNUSED(dp)		((dp)->upper - (dp)->lower)
#define MP_EXTENDED(mp)		((mp)->size > PAGE_SIZE)
#define MP_NEED_SPLIT(mp)	(MP_EXTENDED(mp))

#define MP_ISFULL(mp)						\
	((mp)->size == (16 << PAGE_SHFT) && DP_UNUSED((mp->dp)) < PAGE_SIZE)

typedef struct dinternal {
	uint64_t ksize:8;
	uint64_t pgno:56;
	uint8_t bytes[0];
} __attribute__((packed)) DINTERNAL;

#define	GETDINTERNAL(dp, indx) 						\
	((DINTERNAL *)((char *)(dp) + (dp)->linp[indx]))

#define	NDINTERNAL(len)	(sizeof(DINTERNAL) + len)

/* For the btree leaf pages, the item is a key and data pair. */
typedef struct dleaf {
	uint8_t	ksize;
	uint8_t	dsize;
	uint8_t bytes[0];
} __attribute__((packed)) DLEAF;

/* Get the page's DLEAF structure at index indx. */
#define	GETDLEAF(dp, indx)						\
     ((DLEAF *)((char *)(dp) + (dp)->linp[indx]))

#define NDLEAFDBT(ksize, dsize) 	(sizeof (DLEAF) + ksize + dsize)

/* Get the number of bytes in the entry. */
#define NDLEAF(p)	NDLEAFDBT((p)->ksize, (p)->dsize)

#define DP_ISEMPTY(dp)		((dp)->lower == DP_HDRLEN)
#define MP_ISEMPTY(mp)		(DP_ISEMPTY((mp)->dp))

#define DP_ISLEAF(dp) 		((dp)->flags & DP_LEAF)
#define DP_ISINTERNAL(dp) 	((dp)->flags & DP_INTERNAL)
#define DP_ISMETADATA(dp)	((dp)->flags & DP_METADATA)

#define MP_ISLEAF(mp) 		DP_ISLEAF((mp)->dp)
#define MP_ISINTERNAL(mp) 	DP_ISINTERNAL((mp)->dp)
#define MP_ISMETADATA(mp)	DP_ISMETADATA((mp)->dp)

typedef struct BTREE_s {
	int (*bt_cmp)(const DBT *a, const DBT *b);
} BTREE;

#define DP_MAX_KSIZE	    256
#define DP_MAX_DSIZE	    256
#define BT_MDPGNO	    (0)

extern void		 bt_page_mark_dirty(struct mpage *mp);
extern void		 bt_page_rdlock(struct mpage *mp);
extern void		 bt_page_wrlock(struct mpage *mp);
extern void		 bt_page_unlock(struct mpage *mp);
extern void		 bt_page_free(struct mpage *mp);
extern void		 bt_page_put(struct mpage *mp);
extern struct mpage	*bt_page_get_nowait(pgno_t pgno);
extern struct mpage	*bt_page_get(pgno_t pgno);
extern struct mpage	*bt_page_new(size_t size);
extern int		 bt_page_system_init(void);
extern void		 bt_page_system_exit(void);
#endif
