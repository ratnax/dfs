#ifndef __PG_EXT_H__
#define __PG_EXT_H__

#include "global.h"

/* TODO: move this to bm_ext.h after fixing 'pages' in pm.c */
#define TOTAL_SPACE (1024 * 1024 * 1024)

#define PAGE_SHFT   (9)
#define PAGE_SIZE   (1U<<PAGE_SHFT)
#define PAGE_MASK   (PAGE_SIZE - 1)

typedef int64_t	    pgno_t;
struct mpage;
struct dpage;


/* Common fields between in-memory page struct of page manager and in memory
 * page struct of its clients.
 * @pgno should be the first field for MPG2PG and PG2MPG macros to work. 
 */
#define STRUCT_COMMON_FIELDS						\
	struct {							\
		pgno_t pgno;						\
		struct dpage *dp;					\
		size_t size;		    /* On-disk page size. */	\
	}

#define  PAGE_STRUCT_TLR	STRUCT_COMMON_FIELDS
#define MPAGE_STRUCT_HDR	STRUCT_COMMON_FIELDS	

/* Every on-disk page of page manager client's mush start with this header */
#define DPAGE_STRUCT_HDR						\
	struct {							\
		uint64_t lsn;						\
		uint32_t flags;						\
	} __attribute__((packed))

typedef struct page_mgr pg_mgr_t;
typedef int (*init_mpage_t)(struct mpage *);
typedef void (*exit_mpage_t)(struct mpage *);

extern void		 pm_page_rdlock(pg_mgr_t *, struct mpage *);
extern void		 pm_page_wrlock(pg_mgr_t *, struct mpage *);
extern void		 pm_page_unlock(pg_mgr_t *, struct mpage *);
extern void		 pm_page_delete(pg_mgr_t *, struct mpage *);
extern void		 pm_page_mark_dirty(pg_mgr_t *, struct mpage *);
extern void		 pm_page_put(pg_mgr_t *, struct mpage *);
extern struct mpage	*pm_page_get_new(pg_mgr_t *, pgno_t, size_t);
extern struct mpage	*pm_page_get_nowait(pg_mgr_t *, pgno_t);
extern struct mpage	*pm_page_get(pg_mgr_t *, pgno_t);
extern int		 pm_system_init(int);
extern void		 pm_system_exit(void);
extern pg_mgr_t		*pm_alloc(size_t, init_mpage_t, exit_mpage_t, int);
extern void		 pm_free(pg_mgr_t *);
#endif
