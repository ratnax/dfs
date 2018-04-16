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
};

#define PG_DOP_HDR							\
struct {								\
	uint64_t type:8;						\
	uint64_t pgno:56;						\
	uint64_t lsn;							\
	uint64_t prev_lsn;						\
	uint64_t txid;							\
} __attribute__((packed))

struct pgop_insert {
	PG_DOP_HDR;
	uint16_t rec_len;
	uint16_t ins_idx;
	uint8_t bytes[0];
};

struct pgop_delete {
	PG_DOP_HDR;
	uint16_t rec_len;
	uint16_t del_idx;
	uint8_t bytes[0];
};

struct pgop_replace {
	PG_DOP_HDR;
	uint8_t key_len;
	uint8_t val_len;
	uint16_t rec_len;
	uint16_t rep_idx;
	uint8_t bytes[0];
};

struct pgop_split_old {
	PG_DOP_HDR;
	uint64_t lpgno;
	uint64_t rpgno;
	uint16_t spl_idx;
};

struct pgop_split_left {
	PG_DOP_HDR;
	uint64_t olsn;
	uint64_t opgno;
	uint16_t spl_idx;
};

struct pgop_split_right {
	PG_DOP_HDR;
	uint64_t olsn;
	uint64_t opgno;
	uint16_t spl_idx;
};

struct pgop_split_parent {
	PG_DOP_HDR;
	uint16_t spl_idx;
	uint16_t ins_idx;
	uint64_t olsn;
	uint64_t opgno;
	uint64_t lpgno;
	uint64_t rpgno;
};

struct pgop_split_md {
	PG_DOP_HDR;
	uint64_t opgno;
	uint64_t npgno;
};

struct pgop_blkop {
	PG_DOP_HDR;
	uint16_t bu;
	uint16_t bit;
};

struct pgmop {
	struct list_head lgops;
	size_t size;
	lm_log_t *lg;
	uint8_t dop[0];
};

struct tx_commit_rec {
	uint64_t type:8;
	union {
		uint64_t txid:56;
		uint64_t pgno:56;
	};
};

struct txn {
	uint64_t id;
};

extern int	txn_log_ins(struct txn *tx, uint64_t pgno, uint64_t lsn,
		    void *rec, size_t rec_len, int ins_idx, uint64_t *out_lsn);
extern int	txn_log_del(struct txn *tx, uint64_t pgno, uint64_t lsn,
		    void *rec, size_t rec_len, int del_idx, uint64_t *out_lsn);
extern int	txn_log_rep(struct txn *tx, uint64_t pgno, uint64_t lsn,
		    void *rec, size_t rec_len, void *key, size_t key_len,
		    void *val, size_t val_len, int rep_idx, uint64_t *out_lsn);
extern int	txn_log_split(struct txn *tx, uint64_t ppgno, uint64_t plsn, 
		    uint64_t opgno, uint64_t olsn, uint64_t lpgno,
		    uint64_t rpgno, int idx, int spl_idx, uint64_t *out_olsn, 
		    uint64_t *out_plsn, uint64_t *out_llsn, uint64_t *out_rlsn);
extern int	txn_log_newroot(struct txn *tx, uint64_t ppgno, uint64_t opgno,
		    uint64_t olsn, uint64_t lpgno, uint64_t rpgno,
		    uint64_t mdpgno, uint64_t mdlsn, int ins_idx,
		    int spl_idx, uint64_t *out_olsn, uint64_t *out_plsn,
		    uint64_t *out_llsn, uint64_t *out_rlsn,
		    uint64_t *out_mdlsn);
extern int	txn_log_bmop(struct txn *tx, uint64_t pgno, uint64_t lsn,
		    int bu, int bit, bool, uint64_t *out_lsn); 
extern uint64_t txn_get_next_lsn(void);
extern int	txn_commit_page(uint64_t pgno, void *pg, size_t len);
extern void	txn_system_exit(void);
extern int	txn_system_init(void);
#endif
