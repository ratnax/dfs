#ifndef __BLK_EXT_H__
#define __BLK_EXT_H__ 

#define BLK_SHFT    9
#define BLK_SIZE    (1UL << BLK_SHFT)
#define BLK_MASK    (BLK_SIZE - 1)

typedef int64_t blk_t;

extern long	bm_blk_alloc(int shft);
extern int	bm_blk_free(blk_t blk);
extern bool	bm_blk_alloced(blk_t blk);
extern uint64_t	bm_blk_size(blk_t blk);
extern int	bm_system_init(void);
#endif
