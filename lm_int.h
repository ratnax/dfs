#ifndef __LM_INT_H__
#define __LM_INT_H__

#include "pm_ext.h"
#include "bm_ext.h"
#include "lm_ext.h"
#include "list.h"

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
	sect_mrkr_t  mrkr;
	sect_flgs_t  flgs;
	sect_coff_t  coff[2];
} __attribute ((packed));

#define SECT_FLAG_HDR		(1)
#define LOG_MRKR_SHFT		(sizeof (sect_mrkr_t) << 3)
#define LOG_COFF_SHFT		(sizeof (sect_coff_t) << 3)

#define LOG_ALIGN_SHFT		((SECT_SHFT > LOG_COFF_SHFT) ?	\
				 (SECT_SHFT - LOG_COFF_SHFT) : 0)
#define LOG_ALIGN_SIZE		(1U << LOG_ALIGN_SHFT)
#define LOG_ALIGN_MASK		(LOG_ALIGN_SIZE - 1)

#define LOG_MRKR_INIT		((sect_mrkr_t) 0)
#define LOG_MRKR_PSWITCH(m)	((sect_mrkr_t) (~(m)))	/* partial switch */	
#define LOG_MRKR_FSWITCH(m)	((m) ^			/* full switch */   \
				(((sect_mrkr_t) ~0) >> (LOG_MRKR_SHFT >> 1)))

#define SECT_DLM_SIZE		(sizeof (struct sect_dlm))

#define SECT_HDR_OFFSET		(0)
#define SECT_TLR_OFFSET		((SECT_SIZE - SECT_DLM_SIZE))
#define SECT_DATA_SIZE		(SECT_SIZE - 2 * SECT_DLM_SIZE)

#define LOG_MAX_IOV		(1024)

struct lm_log_t {
	size_t		 size;
	size_t		 size_avail;
	size_t		 part_size;
	uint8_t		 mrkr;
	int		 fd;
	loff_t		 base_offset;
	int		 commit_count;
	void		*zero_sect;
	void		*mmaped_addr;
	struct list_head list;
};

typedef enum { 
	LB_STATE_NOIO,
	LB_STATE_DOIO,
	LB_STATE_INIO,
	LB_STATE_DOSYNC,
} lb_state_t;

#define LB_FLAG_DIRTY	0x1
#define LB_FLAG_FULL	0x2
#define LB_FLAG_FORKED	0x4

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
	size_t		 nreserved;
	int		 err;
	uint64_t	 io_no;
	uint64_t	 seqno;
	uint64_t	 cid;
	struct iovec	*iov;
	void		*sect;
	lm_log_t	*lg;
	struct list_head lbs;
};
#endif
