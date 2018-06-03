#ifndef __LM_EXT_H__
#define __LM_EXT_H__

typedef struct lm_log_t lm_log_t;
typedef struct lg_blk_t lg_blk_t;
typedef struct lg_idx_t lg_idx_t;

struct lg_idx_t {
	loff_t off;
	size_t iovidx;
	lg_blk_t *lb;
};

typedef size_t	(*lm_rcb_t)(void *buf, size_t size, int idx, void *arg);

extern size_t	 log_space_available(lm_log_t *);
extern int	 log_write(lm_log_t *, void *, size_t);
extern int	 log_writev(lm_log_t *, struct iovec *, size_t, size_t);
extern int	 log_put(lm_log_t *);
extern int	 lm_reserve(lg_idx_t *, size_t);
extern int	 lm_reservev(lg_idx_t *, struct iovec *, size_t, size_t);
extern lm_log_t *lm_write(lg_idx_t *, void *, size_t);
extern lm_log_t *lm_writev(lg_idx_t *, struct iovec *, size_t, size_t);
extern int	 lm_commit(void);
extern int	 log_commit(lm_log_t *);
extern int	 log_finish(lm_log_t *);
extern int	 log_recover(lm_log_t *, void *, size_t, int, lm_rcb_t, void *);
extern void	 log_free(lm_log_t *);
extern lm_log_t	*log_alloc(int, loff_t, size_t, void *);
extern long	 lm_mkfs(int, loff_t);
extern bool	 lm_isfull(void);
extern int	 lm_set_valid_range(int, int);
extern int	 lm_scan(lm_rcb_t, void *);
extern void	 lm_system_exit(void);
extern int	 lm_system_init(int, loff_t);
#endif
