#ifndef __BT_EXT_H__
#define __BT_EXT_H__

#include "pm_ext.h"
#include "tx_ext.h"

typedef struct btree BTREE;
typedef struct dbt {
	void	*data;
	size_t	 size;
} DBT;

extern BTREE	*bt_alloc(void);
extern int	 bt_mkfs(int, pgno_t);
extern int	 bt_get(BTREE *, const DBT *, const DBT *);
extern int	 bt_put(struct txn *, BTREE *, const DBT *, const DBT *);
extern int	 bt_del(struct txn *, BTREE *, const DBT *);
extern void	 bt_system_exit(void);
extern int	 bt_system_init(int fd);
extern void	 print_tree(BTREE *t);
#endif
