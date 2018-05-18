#ifndef __TXN_EXT_H__
#define __TXN_EXT_H__
struct txn;
extern struct txn	*txn_alloc(bool);
extern void		 txn_free(struct txn *);
extern int		 txn_commit(struct txn *, bool);
extern void		 tx_system_exit(void);
extern int		 tx_system_init(int);
#endif
