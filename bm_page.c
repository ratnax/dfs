#include "bm_int.h"

static pg_mgr_t *pm;

struct mpage *
bm_page_get(pgno_t pgno)
{
	return pm_page_get(pm, pgno + 1);
}

void
bm_page_put(struct mpage *mp)
{
	return pm_page_put(pm, mp);
}

static int
__init_mpage(struct mpage *mp)
{
	pthread_mutex_init(&mp->mutex, NULL);
	return 0;
}

static void
__exit_mpage(struct mpage *mp)
{
	return;	
}

void
bm_page_system_exit(void)
{
	if (pm)
		pm_free(pm);
}

int 
bm_page_system_init(void)
{
	pm = pm_alloc(sizeof (struct mpage), __init_mpage, __exit_mpage);
	if (IS_ERR(pm)) 
		return PTR_ERR(pm);
	return 0;
}
