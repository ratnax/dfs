#ifndef __TXN_EXT_H__
#define __TXN_EXT_H__
struct txn;
extern struct	txn *txn_alloc(void);
extern void	txn_free(struct txn *);
extern int	txn_commit(struct txn *);
extern void	txn_system_exit(void);
extern int	txn_system_init(void);
#endif
