#ifndef __LM_INT_H__
#define __LM_INT_H__

#include "pm_ext.h"
#include "bm_ext.h"
#include "lm_ext.h"
#include "list.h"
#include "libaio.h"

#define TX_LOG_BLK_SHFT		(20)
#define TX_LOG_BLK_SIZE		(1 << TX_LOG_BLK_SHFT)
#define TX_LOG_NBLKS		(TX_LOG_SPACE >> TX_LOG_BLK_SHFT)

#define SECT_SHFT		(9)
#define SECT_SIZE		(1U << SECT_SHFT)
#define SECT_MASK		(SECT_SIZE - 1)

typedef uint8_t sect_mrkr_t;
typedef uint8_t sect_coff_t;
typedef uint8_t sect_flgs_t;

struct sect_dlm {
	uint8_t	logid:1;
	uint8_t seqno:7;
	uint8_t flags;
	uint8_t coff[2];
} __attribute ((packed));

#define LOG_ALIGN_SHFT		(1)
#define SECT_FLAG_HDR		(1)
#define SECT_DLM_SIZE		(sizeof (struct sect_dlm))

#define SECT_HDR_OFFSET		(0)
#define SECT_TLR_OFFSET		((SECT_SIZE - SECT_DLM_SIZE))
#define SECT_DATA_SIZE		(SECT_SIZE - 2 * SECT_DLM_SIZE)

#define LB_MAX_IOVCNT		(256)

struct lm_log_t {
	size_t		 size;
	size_t		 size_avail;
	size_t		 part_size;
	uint8_t		 logid;
	int		 fd;
	loff_t		 base_offset;
	uint64_t	 seqno;
	int		 commit_count;
	void		*zero_sect;
	void		*sect;
	void		*mmaped_addr;
	uint64_t	 flr_seqno;	/* First log record's seqno, used in 
					 * recovery to sort full logs. */
	struct list_head list;
};

typedef enum { 
	LB_STATE_ACTIVE,
	LB_STATE_DOIO,
	LB_STATE_INIO,
	LB_STATE_DOSYNC,
} lb_state_t;

#define LB_FLAG_AIO		0x1 /* async or aligned IO */
#define LB_FLAG_FULL		0x2 /* corresponding log is full */
#define LB_FLAG_FORKED		0x4 
#define LB_FLAG_NOHDR		0x8

struct lg_blk_t {
    	loff_t		 off;		/* next log offset to write to */
	loff_t		 coff;		/* commit offset */
	struct sect_dlm	 ps_dlm[2];	/* partial sector headers.  */
	struct sect_dlm	 fs_dlm;		/* full sector header */
	uint8_t		 flags;
	lb_state_t	 state;
	uint8_t		 psi;		/* index into psh above */
	size_t		 lsh_iovidx;	/* last sector header iovidx */
	size_t		 fst_iovidx;	/* first sector trailer iovidx */	
	size_t		 iovmax;
	size_t		 iovidx;
	size_t		 io_size;
	int		 last_err;
	struct iovec	 iovecs[LB_MAX_IOVCNT];
	lm_log_t	*lg;
	struct iocb	 iocb;
	struct list_head lbs;
};

#define __mark_aio(lb)		do { (lb)->flags |= LB_FLAG_AIO; }  while (0)	
#define __mark_nohdr(lb)	do { (lb)->flags |= LB_FLAG_NOHDR; } while (0)	
#define __mark_forked(lb)	do { (lb)->flags |= LB_FLAG_FORKED; } while (0)	
#define __mark_full(lb)		do { (lb)->flags |= LB_FLAG_FULL; } while (0)	

#define __sect_floor(off)	((off)  & ~SECT_MASK)
#define __sect_ceiling(off)	(((off) +  SECT_MASK) & ~SECT_MASK) 
#define __sect_mod(off)		((off)  &  SECT_MASK)

#define __is_aio(lb)		((lb)->flags & LB_FLAG_AIO)
#define __is_full(lb)		((lb)->flags & LB_FLAG_FULL)
#define __is_nohdr(lb)		((lb)->flags & LB_FLAG_NOHDR)
#define __is_todel(lb)		((lb)->flags & (LB_FLAG_FULL|LB_FLAG_FORKED))
#define __is_active(lb)		((lb)->state == LB_STATE_ACTIVE)
#endif
