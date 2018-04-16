#ifndef __TXN_EXT_H__
#define __TXN_EXT_H__
struct txn;
extern struct txn	*tx_alloc(void);
extern void		 tx_free(struct txn *);
extern int		 tx_commit(struct txn *);
extern void		 tx_system_exit(void);
extern int		 tx_system_init(int);
#endif
