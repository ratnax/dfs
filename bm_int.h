#ifndef __BLK_INT_H__
#define __BLK_INT_H__

#include "global.h"
#include "pm_ext.h"
#include "bm_ext.h"


#define TOTAL_BLKS	(TOTAL_SPACE >> BLK_SHFT)
#define	MAX_UNIT_TYPE	(9)

/* These macros are in terms of BLK_SIZE quantities. */
#define	MIN_UNIT_SHFT	(PAGE_SHFT - BLK_SHFT)
#define	MIN_UNIT_SIZE	(1UL << MIN_UNIT_SHFT)
#define	MIN_UNIT_MASK	(MIN_UNIT_SIZE - 1)
#define	MAX_UNIT_SHFT	(MIN_UNIT_SHFT + MAX_UNIT_TYPE)
#define	MAX_UNIT_SIZE	(1UL << MAX_UNIT_SHFT)
#define	MAX_UNIT_MASK	(MAX_UNIT_SIZE - 1)
#define	TOTAL_UNITS	(TOTAL_BLKS >> MAX_UNIT_SHFT)

struct bunit {
	uint32_t shft;
	uint32_t rsvd;
	uint32_t nmax;
	uint32_t nfree;
	uint64_t map[1 << (MAX_UNIT_TYPE - 5)];
} __attribute__((packed));

struct dpage {
	DPAGE_STRUCT_HDR;
	struct bunit bu[0];
} __attribute__((packed));

#define DP_HDRLEN	sizeof (struct dpage)
#define	DP_NBUNIT	((PAGE_SIZE - DP_HDRLEN) / sizeof (struct bunit))
#define	MAX_BUPAGES	((TOTAL_UNITS + DP_NBUNIT - 1) / DP_NBUNIT)
#define	BLK2BIT(u, b)	(((b) & MAX_UNIT_MASK) >> (u)->shft)

struct mpage {
	MPAGE_STRUCT_HDR;
	pthread_mutex_t mutex;
};

extern struct mpage	*bm_page_get(pgno_t pgno);
extern void		 bm_page_put(struct mpage *mp);
extern void		 bm_page_system_exit(void);
extern int		 bm_page_system_init(void);
#endif