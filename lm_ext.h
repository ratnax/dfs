#ifndef __LM_EXT_H__
#define __LM_EXT_H__

typedef struct lm_log_t lm_log_t;

typedef size_t	(*lm_cb_t)(void *buf, size_t size, void *arg);

extern size_t	 log_space_available(lm_log_t *);
extern int	 log_write(lm_log_t *, void *, size_t);
extern int	 log_writev(lm_log_t *, struct iovec *, size_t, size_t);
extern int	 log_put(lm_log_t *);
extern lm_log_t	*lm_write(void *, size_t);
extern lm_log_t	*lm_writev(struct iovec *, size_t, size_t);
extern int	 lm_commit(void);
extern int	 log_commit(lm_log_t *);
extern int	 log_finish(lm_log_t *);
extern int	 log_recover(lm_log_t *, void *, size_t, lm_cb_t, void *);
extern void	 log_free(lm_log_t *);
extern lm_log_t	*log_alloc(int, loff_t, size_t, void *);
extern long	 lm_mkfs(int, loff_t);
extern bool	 lm_isfull(void);
extern int	 lm_scan(lm_cb_t, void *);
extern void	 lm_system_exit(void);
extern int	 lm_system_init(int, loff_t);
#endif
