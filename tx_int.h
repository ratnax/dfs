#ifndef __TXN_INT_H__
#define __TXN_INT_H__

#include "global.h"
#include "tx_ext.h"
#include "lm_ext.h"
#include "list.h"

enum pgop_type {
	PGOP_NOP,
	PGOP_INSERT,
	PGOP_DELETE,
	PGOP_REPLACE,
	PGOP_SPLIT_OLD,
	PGOP_SPLIT_LEFT,
	PGOP_SPLIT_RIGHT,
	PGOP_SPLIT_PARENT,
	PGOP_SPLIT_MD,
	PGOP_BLKSET,
	PGOP_BLKRESET,
	PGOP_COMMIT_PAGE,
	PGOP_COMMIT_TXN,
	PGOP_MAXOP,
};

#define PG_DOP_HDR							\
struct {								\
	uint64_t type:8;						\
	uint64_t pgno:56;						\
	uint64_t lsn;							\
	uint64_t prev_lsn;						\
	uint64_t txid;							\
} __attribute__((packed))

typedef PG_DOP_HDR pg_dop_hdr_t;
struct pgop_insert {
	PG_DOP_HDR;
	uint16_t rec_len;
	uint16_t ins_idx;
	uint8_t bytes[0];
} __attribute__((packed));

struct pgop_delete {
	PG_DOP_HDR;
	uint16_t rec_len;
	uint16_t del_idx;
	uint8_t bytes[0];
} __attribute__((packed));

struct pgop_replace {
	PG_DOP_HDR;
	uint8_t key_len;
	uint8_t val_len;
	uint16_t rec_len;
	uint16_t rep_idx;
	uint8_t bytes[0];
} __attribute__((packed));

struct pgop_split_old {
	PG_DOP_HDR;
	uint64_t lpgno;
	uint64_t rpgno;
	uint16_t spl_idx;
} __attribute__((packed));

struct pgop_split_left {
	PG_DOP_HDR;
	uint64_t olsn;
	uint64_t opgno;
	uint16_t spl_idx;
} __attribute__((packed));

struct pgop_split_right {
	PG_DOP_HDR;
	uint64_t olsn;
	uint64_t opgno;
	uint16_t spl_idx;
} __attribute__((packed));

struct pgop_split_parent {
	PG_DOP_HDR;
	uint16_t spl_idx;
	uint16_t ins_idx;
	uint64_t olsn;
	uint64_t opgno;
	uint64_t lpgno;
	uint64_t rpgno;
} __attribute__((packed));

struct pgop_split_md {
	PG_DOP_HDR;
	uint64_t opgno;
	uint64_t npgno;
} __attribute__((packed));

struct pgop_blkop {
	PG_DOP_HDR;
	uint16_t bu;
	uint16_t bit;
} __attribute__((packed));

struct pgdop_info {
	uint64_t pgno;
	uint64_t lsn;
	uint64_t prev_lsn;
};

struct pgmop_info {
	struct list_head	 pgops;
	struct pgmop		*mop;
};

struct pgdop {
	uint64_t		txid;	
	uint16_t		npg;
	struct pgdop_info	pginfo[0];
} __attribute__ ((packed));

struct pgmop {
	lm_log_t		*lg;
	struct txn		*tx;
	struct list_head	 lgops;
	struct list_head	 txops;
	size_t			 size;
	struct pgdop		*dop;
	struct pgmop_info	 pginfo[0];
};

struct tx_commit_rec {
	uint64_t type:8;
	union {
		uint64_t txid:56;
		uint64_t pgno:56;
	} __attribute__((packed));
} __attribute__((packed));

struct txn {
	uint64_t		 id;
	struct list_head	 mops;
	struct list_head	 txs;
	struct pgmop		*mop;
	int			 npg_cmted;
	int			 npg_total;
};

typedef void (*tx_commit_cb_t)(void *);

extern int	txn_log_op(struct txn *tx, int npg, size_t len, char *fmt1,
		    char *fmt2, ...);
extern int	txn_commit_page(struct list_head *head, int err);
extern int	txn_commit_page_deleted(struct list_head *head);
//extern int	txn_log_page(struct page *pg, void *data, size_t size);
#endif
