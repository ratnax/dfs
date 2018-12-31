#ifndef __LM_EXT_H__
#define __LM_EXT_H__

typedef struct lm_log_t lm_log_t;
typedef struct lg_blk_t lg_blk_t;
typedef struct lm_idx_t lm_idx_t;
typedef struct lb_rec_t lb_rec_t;
typedef struct lr_hdr_t lr_hdr_t;

struct lm_idx_t {
	lm_log_t *lg1;
	lm_log_t *lg2;
	loff_t	soff;
	loff_t	eoff;
};

struct lr_hdr_t {
	uint64_t	lsn;
	uint16_t	len;
} __attribute ((packed));

struct lb_rec_t {
	lr_hdr_t	hdr;
	uint8_t		data[0];
} __attribute ((packed));

typedef size_t	(*lm_rcb_t)(void *buf, size_t size, void *arg);

extern size_t	 log_space_available(lm_log_t *);
extern int	 log_write(lm_log_t *, void *, size_t);
extern int	 log_writev(lm_log_t *, struct iovec *, size_t, size_t);
extern int	 log_put(lm_log_t *);
extern int	 lm_write(void *data, size_t size, lm_idx_t *);
extern int	 lm_commit(lm_log_t *lg, loff_t off);
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
