#ifndef __MM_EXT_H__
#define __MM_EXT_H__

typedef struct mem_blk mm_blk_t;
extern mm_blk_t *mm_reserve(void);
extern void  mm_unreserve(mm_blk_t *mb);
extern void *mm_alloc(mm_blk_t *mb, size_t size);
extern void  mm_free(mm_blk_t *mb, void *p, size_t size);
#endif
