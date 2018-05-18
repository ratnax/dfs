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

typedef uint8_t log_mrkr_t;
typedef uint8_t log_coff_t;

struct sect_dlm {
	log_mrkr_t  mrkr;
	log_coff_t  coff;
};

#define LOG_MRKR_SHFT		(sizeof (log_mrkr_t) << 3)
#define LOG_COFF_SHFT		(sizeof (log_coff_t) << 3)

#define LOG_ALIGN_SHFT		((SECT_SHFT > LOG_COFF_SHFT) ?	\
				 (SECT_SHFT - LOG_COFF_SHFT) : 0)
#define LOG_ALIGN_SIZE		(1U << LOG_ALIGN_SHFT)
#define LOG_ALIGN_MASK		(LOG_ALIGN_SIZE - 1)

#define LOG_MRKR_INIT		((log_mrkr_t) 0)
#define LOG_MRKR_PSWITCH(m)	((log_mrkr_t) (~(m)))	/* partial switch */	
#define LOG_MRKR_FSWITCH(m)	((m) ^			/* full switch */   \
				(((log_mrkr_t) ~0) >> (LOG_MRKR_SHFT >> 1)))

#define SECT_DLM_SIZE		(sizeof (struct sect_dlm))

#define SECT_HDR_OFFSET		(0)
#define SECT_TLR_OFFSET		((SECT_SIZE - SECT_DLM_SIZE))
#define SECT_DATA_SIZE		(SECT_SIZE - 2 * SECT_DLM_SIZE)

#define LOG_MAX_IOV		(1024)

struct lm_log_t {
	loff_t	 off;			/* next log offset to write to */
	loff_t	 coff;			/* commit offset */
	loff_t	 base_offset;
	size_t	 size;
	uint8_t  mrkr;
	struct	 sect_dlm psh[2];	/* partial sector headers.  */
	struct	 sect_dlm pst[2];	/* partial sector trailers. */
	struct	 sect_dlm fsh;		/* full sector header */
	struct	 sect_dlm fst;		/* full sector trailer */
	uint8_t  pshi;			/* index into psh above */
	uint8_t  psti;			/* index into pst above */
	int	 fd;
	int	 commit_count;
	size_t	 lsh_iovidx;		/* last sector header iovidx */
	size_t	 fst_iovidx;		/* first sector trailer iovidx */	
	size_t	 iovmax;
	size_t	 iovidx;
	struct	 iovec *iov;
	void	*sect;
	void	*zero_sect;
	void	*mmaped_addr;
	struct	 list_head list;
};
#endif
