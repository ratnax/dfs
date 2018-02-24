#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "mp_mem.h"

static TAILQ_HEAD(reorg_queue, mpage) reorg_queue_head;

static pthread_mutex_t reorg_queue_mutex;
static pthread_cond_t reorg_queue_cond;


static void
__wr_dinternal(void *dest, void *key, size_t ksize, pgno_t pgno)
{
	DINTERNAL *di = (DINTERNAL *) dest;

	di->ksize = ksize;
	di->pgno = pgno;
	memcpy(di->bytes, key, ksize); 
}


static void
__wr_dleaf(void *dest, const DBT *key, const DBT *val)
{
	DLEAF *dl = (DLEAF *) dest;

	dl->ksize = key->size;
	dl->dsize = val->size;
	memcpy((void *) (dl->bytes), key->data, key->size); 
	memcpy((void *) (dl->bytes) + key->size, key->data, val->size); 
}

static int
__bt_cmp(BTREE *t, const DBT *k1, struct mpage *mp, int indx)
{
	struct dpage *dp = mp->dp; 
	DBT k2;

	/*
	 * The left-most key on internal pages, at any level of the tree, is
	 * guaranteed by the following code to be less than any user key.
	 * This saves us from having to update the leftmost key on an internal
	 * page when the user inserts a new key in the tree smaller than
	 * anything we've yet seen.
	 */
	if (indx == 0 && dp->flags & DP_BINTERNAL)
		return (1);

	if (dp->flags & DP_BLEAF) {
		DLEAF *dl = GETDLEAF(dp, indx);
		k2.data = dl->bytes;
		k2.size = dl->ksize;
	} else {
		DINTERNAL *di = GETDINTERNAL(dp, indx);
		k2.data = di->bytes;
		k2.size = di->ksize;
	}
	return ((*t->bt_cmp)(k1, &k2));
}

static int
__bt_defcmp(const DBT *a, const DBT *b)
{
	register size_t len;
	register unsigned char *p1, *p2;

	len = MIN(a->size, b->size);
	for (p1 = a->data, p2 = b->data; len--; ++p1, ++p2)
		if (*p1 != *p2)
			return ((int)*p1 - (int)*p2);
	return ((int)a->size - (int)b->size);
}

static bool 
__lookup(BTREE *t, struct mpage *mp, const DBT *key, indx_t *indxp)
{
	struct dpage *dp = mp->dp; 
	indx_t base, lim;

	for (base = 0, lim = DP_NXTINDX(dp); lim; lim >>= 1) {
		indx_t indx = base + (lim >> 1);
		int cmp;

		if ((cmp = __bt_cmp(t, key, mp, indx)) == 0) {
			*indxp = indx;
			return true;
		}
		if (cmp > 0) {
			base = indx + 1;
			--lim;
		}
	}

	*indxp = base;
	return false;
}

static pgno_t
__lookup_internal(BTREE *t, struct mpage *mp, const DBT *key, indx_t *indxp)
{
	struct dpage *dp = mp->dp;
	indx_t indx;
	bool exact;

	if (!(exact = __lookup(t, mp, key, &indx))) 
		indx -= indx ? 1 : 0;

	*indxp = indx;
	return GETDINTERNAL(dp, indx)->pgno;
}

static bool
__lookup_leaf(BTREE *t, struct mpage *mp, const DBT *key, indx_t *indxp)
{
	return __lookup(t, mp, key, indxp); 
}

static struct mpage *
__lookup_parent_nowait(BTREE *t, struct mpage *g_mp, struct mpage *p_mp, 
						const DBT *key, indx_t *indxp)
{
	struct mpage *mp;
	pgno_t pgno;

	pgno = __lookup_internal(t, p_mp, key, indxp);
	if ((mp = bt_page_get_nowait(pgno))) {
		mp->leftmost = (*indxp == 0 && p_mp->leftmost);
		return mp;
	}
			
	bt_page_unlock(p_mp);
	if (g_mp)
		bt_page_unlock(g_mp);

	mp = bt_page_get(pgno);
	if (IS_ERR(mp)) 
		return mp;
	else {
		bt_page_put(mp);
		return ERR_PTR(EAGAIN);
	}
}

static int
__read_data(BTREE *t, struct mpage *mp, const DBT *key, const DBT *val)
{
	int err = 0;
	indx_t indx;
	bool exact;
	struct dpage *dp  = mp->dp;
	
	exact = __lookup_leaf(t, mp, key, &indx);
	if (exact) {
		DLEAF *dl = GETDLEAF(dp, indx);
		memcpy(val->data, dl->bytes + dl->ksize, dl->dsize);
	} else {
		err = -ENOENT;
	}
	bt_page_unlock(mp);
	return err;
}

static struct mpage * __bt_get_root(struct mpage *md_pg)
{
	struct mpage *mp;

	do {
		mp = bt_page_get_nowait(md_pg->md->root_pgno);
		if (IS_ERR(mp)) {
			if (PTR_ERR(mp) != EAGAIN) {
				bt_page_unlock(md_pg);
				return mp;
			}
		} else
			break;

		bt_page_unlock(md_pg);

		mp = bt_page_get(md_pg->md->root_pgno);
		if (IS_ERR(mp))
			return mp;

		bt_page_lock(md_pg, PAGE_LOCK_SHARED);
	} while (mp->pgno != md_pg->md->root_pgno);

	mp->leftmost = true;
	return mp;
}
			
struct mpage *__get_md_page(void)
{
	struct mpage *mp;
	mp = bt_page_get(P_MDPGNO);
	if (IS_ERR(mp))
		return mp;

	MP_SET_METADATA(mp);
	return mp;
}

static int __wait_on_reorg(struct mpage *mp, struct mpage *pmp)
{
	if (MP_REORGING(mp)) {
		bt_page_unlock(mp);
		if (pmp)
			bt_page_unlock(pmp);

		pthread_mutex_lock(&mp->mutex);
		while (MP_REORGING(mp)) 
			pthread_cond_wait(&mp->cond, &mp->mutex);
		pthread_mutex_unlock(&mp->mutex);

		bt_page_put(mp);
		return -EAGAIN;
	}
	return 0;
}

static struct mpage *
__bt_get_leaf_locked(BTREE *t, const DBT *key, int excl)
{
	struct mpage *mp, *p_mp = NULL;
	indx_t indx;
	int err;

	do {
		p_mp = __get_md_page();
		if (IS_ERR(p_mp))
			return p_mp;

		bt_page_lock(p_mp, PAGE_LOCK_SHARED);

		mp = __bt_get_root(p_mp);
		if (IS_ERR(mp)) {
			bt_page_unlock(p_mp);
			bt_page_put(p_mp);
			return mp;
		}

		while (!IS_ERR(mp)) {

			if (MP_ISINTERNAL(mp)) {
				bt_page_lock(mp, PAGE_LOCK_SHARED);

				err = __wait_on_reorg(mp, p_mp);
				if (err) {
					mp = ERR_PTR(EAGAIN);
					break;
				}

				bt_page_unlock(p_mp);
				bt_page_put(p_mp);
			} else {

				if (excl) {
					bt_page_lock(mp, PAGE_LOCK_EXCL);

					err = __wait_on_reorg(mp, p_mp);
					if (err) {
						mp = ERR_PTR(EAGAIN);
						break;
					}
				} else {
					bt_page_lock(mp, PAGE_LOCK_SHARED);
				}

				bt_page_unlock(p_mp);
				bt_page_put(p_mp);
				return mp;
			}

			p_mp = mp;
			mp = __lookup_parent_nowait(t, NULL, p_mp, key, &indx);
		}

		bt_page_put(p_mp);
	} while (PTR_ERR(mp) == EAGAIN);

	return mp;
}

static struct mpage *__bt_get_leaf_excl(BTREE *t, const DBT *key)
{
	return __bt_get_leaf_locked(t, key, true);
}

static struct mpage *__bt_get_leaf_shared(BTREE *t, const DBT *key)
{
	return __bt_get_leaf_locked(t, key, false);
}

static struct mpage * 
__get_parent_locked(BTREE *t, struct mpage *c_mp, indx_t *indxp, bool excl)
{
	struct mpage *mp, *g_mp, *p_mp = NULL;
	char key_mem[DP_MAX_KSIZE];
	DBT key;
	pgno_t pgno;
	int err;
	
	bt_page_lock(c_mp, PAGE_LOCK_SHARED); 
	if (MP_ISLEAF(c_mp)) {

		DLEAF *dl = GETDLEAF(c_mp->dp, 0);
		memcpy(key_mem, dl->bytes, dl->ksize);
		key.data = key_mem;
		key.size = dl->ksize;
	} else { 	

		DINTERNAL *di;
		if (DP_NXTINDX(c_mp->dp) > 1)
			di = GETDINTERNAL(c_mp->dp, 1);
		else
			di = GETDINTERNAL(c_mp->dp, 0);
		memcpy(key_mem, di->bytes, di->ksize);
		key.data = key_mem;
		key.size = di->ksize;
	}
	bt_page_unlock(c_mp); 

	do {
		g_mp = __get_md_page();
		if (IS_ERR(g_mp))
			return g_mp;

		bt_page_lock(g_mp, PAGE_LOCK_SHARED);

		mp = __bt_get_root(g_mp);
		if (mp->pgno == c_mp->pgno) {
			bt_page_put(mp);
			if (excl) {
				bt_page_unlock(g_mp);
				bt_page_lock(g_mp, PAGE_LOCK_EXCL);
			}
			return g_mp;
		} else {
			p_mp = mp;
			bt_page_lock(p_mp, PAGE_LOCK_SHARED);
			mp = __lookup_parent_nowait(t, g_mp, p_mp, &key, indxp);
		}

		while (!IS_ERR(mp)) {
			if (mp->pgno == c_mp->pgno) {

				if (excl) {
					bt_page_unlock(p_mp);
					bt_page_put(mp);

					bt_page_lock(p_mp, PAGE_LOCK_EXCL);
					err = __wait_on_reorg(p_mp, g_mp);
					if (err) {
						p_mp = NULL;
						mp = ERR_PTR(EAGAIN);
						break;
					}
					bt_page_unlock(g_mp);
					bt_page_put(g_mp);
			
					pgno = __lookup_internal(t, p_mp, &key, indxp);
					assert(c_mp->pgno == pgno);

					return p_mp;
				} else {
					bt_page_unlock(g_mp);
					bt_page_put(g_mp);
					bt_page_put(mp);
					return p_mp;
				}
			} else { 

				bt_page_unlock(g_mp);
				bt_page_put(g_mp);

				bt_page_lock(mp, PAGE_LOCK_SHARED);

				err = __wait_on_reorg(mp, p_mp);
				if (err) {
					g_mp = NULL;
					mp = ERR_PTR(EAGAIN);
					break;
				}

				g_mp = p_mp;
				p_mp = mp;	
				mp = __lookup_parent_nowait(t, g_mp, p_mp, &key, indxp);
			}
		}

		if (p_mp)
			bt_page_put(p_mp);
		if (g_mp)
			bt_page_put(g_mp);
	} while (PTR_ERR(mp) == EAGAIN);

	return mp;
}

static struct mpage * 
__get_parent_excl(BTREE *t, struct mpage *c_mp, indx_t *indxp)
{
	return __get_parent_locked(t, c_mp, indxp, true);
}

static struct mpage * 
__get_parent_shared(BTREE *t, struct mpage *c_mp, indx_t *indxp)
{
	return __get_parent_locked(t, c_mp, indxp, false);
}

static int __bt_page_extend(BTREE *t, struct mpage *mp)
{
	struct dpage *dp, *old_dp = mp->dp;
	size_t size = PAGE_SIZE * mp->npg;
	int i;

	dp = malloc(size + PAGE_SIZE);
	if (!dp)
		return -ENOMEM;

	dp->upper = old_dp->upper + PAGE_SIZE;
	dp->lower = old_dp->lower;
	dp->flags = old_dp->flags;

	memcpy((void *) dp + dp->upper, (void *) old_dp + old_dp->upper, 
			size - mp->dp->upper); 

	for (i = 0; i < DP_NXTINDX(old_dp); i++) 
		dp->linp[i] = old_dp->linp[i] + PAGE_SIZE;

	mp->dp = dp;
	mp->npg = mp->npg + 1;
	free(old_dp);
	return 0;
}

static int __bt_page_shrink(BTREE *t, struct mpage *mp)
{
	struct dpage *dp = mp->dp;
	struct dpage *new_dp;
	size_t i, shift;

	if (mp->npg == 1 || 
		dp->upper - dp->lower < (shift = mp->npg - 1 << PAGE_SHFT))
		return 0;

	new_dp = malloc(PAGE_SIZE);
	if (!new_dp)
		return -ENOMEM;

	new_dp->upper = dp->upper - shift;
	new_dp->lower = dp->lower;
	new_dp->flags = dp->flags;

	memcpy((void *) new_dp + new_dp->upper, (void *) dp + dp->upper, 
			PAGE_SIZE - new_dp->upper);  

	for (i = 0; i < DP_NXTINDX(dp); i++) 
		new_dp->linp[i] = dp->linp[i] - shift;

	mp->dp = new_dp;
	mp->npg = 1; 
	free(dp);
	return 0;
}

static bool 
__insert_leaf_at(BTREE *t, struct mpage *mp, const DBT *key, const DBT *val,
				indx_t indx)
{
	struct dpage *old_dp, *dp = mp->dp;
	size_t nbytes;
	indx_t nxtindx;
	int err;

	nbytes = NDLEAFDBT(key->size, val->size);

	old_dp = dp;
	if (dp->upper - dp->lower < nbytes + sizeof(indx_t)) {
		err = __bt_page_extend(t, mp);
		assert(!err);

		dp = mp->dp;
	}

	if (indx < (nxtindx = DP_NXTINDX(dp))) {
		memmove(dp->linp + indx + 1, dp->linp + indx,
		    (nxtindx - indx) * sizeof(indx_t));
	}

	dp->lower += sizeof(indx_t);
	dp->linp[indx] = dp->upper -= nbytes;

	__wr_dleaf((void *) dp + dp->upper, key, val);
	return (dp != old_dp);
}

static bool 
__remove_leaf_at(struct mpage *mp, const DBT *key, indx_t indx)
{
	DLEAF *dl;
	indx_t cnt, *ip, offset;
	uint32_t nbytes;
	void *to;
	char *from;
	struct dpage *dp = mp->dp;

	/* If the entry uses overflow pages, make them available for reuse. */
	to = dl = GETDLEAF(dp, indx);

	/* Pack the remaining key/data items at the end of the page. */
	nbytes = NDLEAF(dl);
	from = (char *) dp + dp->upper;
	memmove(from + nbytes, from, (char *)to - from);
	dp->upper += nbytes;

	/* Adjust the indices' offsets, shift the indices down. */
	offset = dp->linp[indx];
	for (cnt = indx, ip = &dp->linp[0]; cnt--; ++ip)
		if (ip[0] < offset)
			ip[0] += nbytes;
	for (cnt = DP_NXTINDX(dp) - indx; --cnt; ++ip)
		ip[0] = ip[1] < offset ? ip[1] + nbytes : ip[1];
	dp->lower -= sizeof(indx_t);

	return MP_ISEMPTY(mp);
}

static bool 
__remove_internal_at(struct mpage *mp, DBT *key, indx_t indx)
{
	DINTERNAL *di;
	indx_t cnt, *ip, offset;
	uint32_t nbytes;
	void *to;
	char *from;
	struct dpage *dp = mp->dp;

	if (indx == 1 && DP_NXTINDX(dp) == 2) {
		DINTERNAL *next_di;
		indx_t tmp;

		di = GETDINTERNAL(dp, 0);
		next_di = GETDINTERNAL(dp, 1);

		tmp = dp->linp[0];
		dp->linp[0] = dp->linp[1];
		dp->linp[1] = tmp;

		next_di->pgno = di->pgno;
	}
	
	/* If the entry uses overflow pages, make them available for reuse. */
	to = di = GETDINTERNAL(dp, indx);

	/* Pack the remaining key/data items at the end of the page. */
	nbytes = NDINTERNAL(di->ksize);
	from = (char *) dp + dp->upper;
	memmove(from + nbytes, from, (char *)to - from);
	dp->upper += nbytes;

	/* Adjust the indices' offsets, shift the indices down. */
	offset = dp->linp[indx];
	for (cnt = indx, ip = &dp->linp[0]; cnt--; ++ip)
		if (ip[0] < offset)
			ip[0] += nbytes;
	for (cnt = DP_NXTINDX(dp) - indx; --cnt; ++ip)
		ip[0] = ip[1] < offset ? ip[1] + nbytes : ip[1];
	dp->lower -= sizeof(indx_t);

	return MP_ISEMPTY(mp);
}


static int __bt_get(BTREE *t, const DBT *key, const DBT *val)
{
	int err;
	struct mpage *mp;
	
	mp = __bt_get_leaf_shared(t, key);
	if (IS_ERR(mp)) {
		return PTR_ERR(mp);
	}

	err = __read_data(t, mp, key, val);
	bt_page_put(mp);
	return err;
}

static void __signal_state_change(struct mpage *mp)
{
	pthread_mutex_lock(&mp->mutex);
	pthread_cond_broadcast(&mp->cond);
	pthread_mutex_unlock(&mp->mutex);
}

static void __set_state_deleted(struct mpage *mp)
{
	pthread_mutex_lock(&mp->mutex);
	printf("%d MP_STATE_DELETED\n", mp->pgno);
	mp->state = MP_STATE_DELETED;
	pthread_mutex_unlock(&mp->mutex);
	pthread_cond_broadcast(&mp->cond);
}

static void __set_state_normal(struct mpage *mp)
{
	printf("%d MP_STATE_NORMAL\n", mp->pgno);
	mp->state = MP_STATE_NORMAL;
}

static void __set_state_inreorgq(struct mpage *mp)
{
	printf("%d MP_STATE_INREORGQ\n", mp->pgno);
	mp->state = MP_STATE_INREORGQ;
}

void __set_state_prereorg(struct mpage *mp)
{
	printf("%d MP_STATE_PREREORG\n", mp->pgno);
	mp->state = MP_STATE_PREREORG;
}

static void __set_state_reorging(struct mpage *mp)
{
	printf("%d MP_STATE_REORGING\n", mp->pgno);
	mp->state = MP_STATE_REORGING;
}

static void __set_state_deleting(struct mpage *mp)
{
	printf("%d deleting\n", mp->pgno);
	__set_state_reorging(mp);
}

static void __set_state_splitting(struct mpage *mp)
{
	printf("%d splitting\n", mp->pgno);
	__set_state_reorging(mp);
}

static bool __insert_reorg_queue(struct mpage *mp) 
{
	bool inserted = false;
	assert(mp->pgno);
	pthread_mutex_lock(&reorg_queue_mutex);
	if (MP_NORMAL(mp)) {
		TAILQ_INSERT_TAIL(&reorg_queue_head, mp, reorg_queue_entry);
		__set_state_inreorgq(mp);
		pthread_cond_signal(&reorg_queue_cond);
		inserted = true;
	}
	pthread_mutex_unlock(&reorg_queue_mutex);
	return inserted;
}

static bool __insert_split_queue(struct mpage *mp)
{
	return __insert_reorg_queue(mp);
}

static bool __insert_delete_queue(struct mpage *mp)
{
	return __insert_reorg_queue(mp);
}

static int 
__bt_psplit(BTREE *t, struct mpage *mp, struct mpage **out_left, 
			struct mpage **out_right)
{
	void *src;
	DLEAF *dl;
	DINTERNAL *di;
	indx_t full, half, nxt, off, skip, top, used;
	uint32_t nbytes, len, npg;

	struct mpage *l_mp, *r_mp;
	struct dpage *dp = mp->dp;
	struct dpage *ldp;
	struct dpage *rdp;

	/*
	 * Split the data to the left and right pages.  Leave the skip index
	 * open.  Additionally, make some effort not to split on an overflow
	 * key.  This makes internal page processing faster and can save
	 * space as overflow keys used by internal pages are never deleted.
	 */
	len = (dp->lower - DP_HDRLEN + PAGE_SIZE * mp->npg - dp->upper);
	if (dp->flags & DP_BLEAF) 
		len += NDLEAFDBT(DP_MAX_KSIZE, DP_MAX_DSIZE) + sizeof(indx_t) + 1;
	else 
		len += NDINTERNAL(DP_MAX_KSIZE) + sizeof(indx_t) + 1;
	half = len / 2 + DP_HDRLEN;

	npg = (half + PAGE_MASK) >> PAGE_SHFT;

	l_mp = bt_page_new(npg);
	assert(l_mp);

	r_mp = bt_page_new(npg);
	assert(r_mp);
	
	ldp = l_mp->dp;
	rdp = r_mp->dp;

	ldp->flags = rdp->flags = dp->flags & DP_TYPE;
	rdp->lower = ldp->lower = DP_HDRLEN;
	rdp->upper = ldp->upper = npg * PAGE_SIZE;

	used = 0;
	for (nxt = off = 0, top = DP_NXTINDX(dp); nxt < top; ++off) {
		switch (dp->flags & DP_TYPE) {
		case DP_BINTERNAL:
			src = di = GETDINTERNAL(dp, nxt);
			nbytes = NDINTERNAL(di->ksize);
			break;
		case DP_BLEAF:
			src = dl = GETDLEAF(dp, nxt);
			nbytes = NDLEAF(dl);
			break;
		default:
			assert(0);
		}

		if (used + nbytes + sizeof(indx_t) > npg * PAGE_SIZE - DP_HDRLEN ||
			nxt + 1 == top) {
			assert(off);
			--off;
			break;
		}

		nxt++;
		ldp->linp[off] = ldp->upper -= nbytes;
		memmove((char *)ldp + ldp->upper, src, nbytes);

		used += nbytes + sizeof(indx_t);
		if (used >= half) 
			break;
	}

	/*
	 * Off is the last offset that's valid for the left page.
	 * Nxt is the first offset to be placed on the right page.
	 */
	ldp->lower += (off + 1) * sizeof(indx_t);
	assert(DP_NXTINDX(ldp));

	assert(nxt < top);
	for (off = 0; nxt < top; ++off) {
		switch (dp->flags & DP_TYPE) {
		case DP_BINTERNAL:
			src = di = GETDINTERNAL(dp, nxt);
			nbytes = NDINTERNAL(di->ksize);
			break;
		case DP_BLEAF:
			src = dl = GETDLEAF(dp, nxt);
			nbytes = NDLEAF(dl);
			break;
		default:
			assert(0);
		}
		nxt++;
		rdp->linp[off] = rdp->upper -= nbytes;
		memmove((char *)rdp + rdp->upper, src, nbytes);
	}
	rdp->lower += off * sizeof(indx_t);

	assert(ldp->lower <= ldp->upper);
	assert(rdp->lower <= rdp->upper);

	*out_left = l_mp;
	*out_right = r_mp;
	return 0;
}

static void __bt_root(BTREE *t, struct mpage *mp, struct mpage *pmp, 
	struct mpage *lmp, struct mpage *rmp)
{
	struct dpage *ldp, *rdp, *pdp;
	uint32_t nbytes;
	void *dest;
	DLEAF *dl;
	DINTERNAL *di;

	pdp = pmp->dp;
	rdp = rmp->dp;
	ldp = lmp->dp;

	ldp->flags =  
	rdp->flags = mp->dp->flags & DP_TYPE;

	assert(DP_NXTINDX(ldp));
	assert(DP_NXTINDX(rdp));
	
	nbytes = NDINTERNAL(0);
	pdp->linp[0] = pdp->upper = PAGE_SIZE - nbytes;
	dest = (char *) pdp + pdp->upper;
	__wr_dinternal(dest, NULL, 0, lmp->pgno);
	
	switch (rdp->flags & DP_TYPE) {
	case DP_BLEAF:
		dl = GETDLEAF(rdp, 0);
		nbytes = NDINTERNAL(dl->ksize);
		pdp->linp[1] = pdp->upper -= nbytes;
		dest = (char *)pdp + pdp->upper;
		__wr_dinternal(dest, dl->bytes, dl->ksize, rmp->pgno);
		break;
	case DP_BINTERNAL:
		di = GETDINTERNAL(rdp, 0);
		nbytes = NDINTERNAL(di->ksize);
		pdp->linp[1] = pdp->upper -= nbytes;
		dest = (char *)pdp + pdp->upper;
		__wr_dinternal(dest, di->bytes, di->ksize, rmp->pgno);
		break;
	default:
		assert(0);
	}

	/* There are two keys on the page. */
	pdp->lower = DP_HDRLEN + 2 * sizeof(indx_t);

	/* Unpin the root page, set to btree internal page. */
	pdp->flags = 0;
	pdp->flags |= DP_BINTERNAL;

	pmp->leftmost = true;
}

static bool 
__bt_page(BTREE *t, struct mpage *mp, struct mpage *p_mp, indx_t indx,
	struct mpage *l_mp, struct mpage *r_mp)
{
	struct dpage *rdp, *ldp, *pdp, *old_pdp;
	void *dest;
	uint32_t nbytes;
	DLEAF *dl;
	DINTERNAL *di;
	int err;
	indx_t nxtindx;
	int i;

	rdp = r_mp->dp;
	ldp = l_mp->dp;
	old_pdp = pdp = p_mp->dp;

	switch (rdp->flags & DP_TYPE) {
	case DP_BINTERNAL:
		di = GETDINTERNAL(rdp, 0);
		nbytes = NDINTERNAL(di->ksize);
		break;
	case DP_BLEAF:
		dl = GETDLEAF(rdp, 0);
		nbytes = NDINTERNAL(dl->ksize);
		break;
	default:
		assert(0);
	}

	/* Split the parent page if necessary or shift the indices. */
	if (pdp->upper - pdp->lower < nbytes + sizeof(indx_t)) {
		err = __bt_page_extend(t, p_mp);
		assert(!err);

		pdp = p_mp->dp;
	}	

	nxtindx = DP_NXTINDX(pdp);
	memmove(pdp->linp + indx + 1, pdp->linp + indx,
			    (nxtindx - indx) * sizeof(indx_t));
	pdp->lower += sizeof(indx_t);

	/* Insert the key into the parent page. */
	switch (rdp->flags & DP_TYPE) {
	case DP_BINTERNAL:
		pdp->linp[indx + 1] = pdp->upper -= nbytes;
		dest = (char *) pdp + pdp->linp[indx + 1];
		__wr_dinternal(dest, di->bytes, di->ksize, r_mp->pgno);
		break;

	case DP_BLEAF:
	
		pdp->linp[indx + 1] = pdp->upper -= nbytes;
		dest = (char *) pdp + pdp->linp[indx + 1];
		__wr_dinternal(dest, dl->bytes, dl->ksize, r_mp->pgno);

		break;
	default:
		assert(0);	
	}

	di = GETDINTERNAL(pdp, indx);
	di->pgno = l_mp->pgno;
	return pdp != old_pdp;
}

static int __bt_split(BTREE *t, struct mpage *mp)
{
	struct mpage *lmp, *rmp, *pmp, *new_root, *delete_mp;
	indx_t indx;
	bool lmp_need_split;
	bool rmp_need_split;
	bool pmp_need_split = false;
	int err;

	err = __bt_psplit(t, mp, &lmp, &rmp);
	assert(!err);

	delete_mp = new_root = NULL;
	do {
		pmp = __get_parent_excl(t, mp, &indx);
		if (IS_ERR(pmp)) {
			assert(0);
			return PTR_ERR(pmp);
		}

		if (MP_METADATA(pmp)) {
			
			assert(pmp->pgno == BT_MDPGNO);

			if (!new_root) {

				bt_page_unlock(pmp);
				bt_page_put(pmp);
				pmp = NULL;

				delete_mp = new_root = bt_page_new(1);
				if (IS_ERR(new_root)) {
					assert(0);
					return PTR_ERR(new_root);
				}
			} else {
				__bt_root(t, mp, new_root, lmp, rmp);
				pmp->md->root_pgno = new_root->pgno;
				
				delete_mp = NULL;
			}
		} else {
			pmp_need_split = __bt_page(t, mp, pmp, indx, lmp, rmp);
		}
	} while (!pmp);
	
	lmp_need_split = MP_NEED_SPLIT(lmp);
	rmp_need_split = MP_NEED_SPLIT(rmp);
	bt_page_unlock(pmp);

	__set_state_deleted(mp);

	if (!lmp_need_split || !__insert_split_queue(lmp))
		bt_page_put(lmp);

	if (!rmp_need_split || !__insert_split_queue(rmp))
		bt_page_put(rmp);

	if (!pmp_need_split || !__insert_split_queue(pmp))
		bt_page_put(pmp);

	if (delete_mp) 
		__set_state_deleted(delete_mp);
	if (new_root) 
		bt_page_put(new_root);
	return 0;
}

struct mpage * __bt_delete(BTREE *t, struct mpage *mp)
{
	struct mpage *pmp;
	struct dpage *dp;
	indx_t indx;
	int i;
	bool empty;

	pmp = __get_parent_excl(t, mp, &indx);
	if (IS_ERR(pmp))
		return pmp;

	if (MP_METADATA(pmp)) {

		bt_page_unlock(pmp);
		bt_page_put(pmp);

		bt_page_lock(mp, PAGE_LOCK_EXCL);

		dp = mp->dp;

		dp->flags &= ~DP_BINTERNAL;
		dp->flags |= DP_BLEAF;
		dp->lower = DP_HDRLEN;
		dp->upper = mp->npg * PAGE_SIZE; /* xxx: extened ? */
		bt_page_unlock(mp);

		__set_state_normal(mp);
		/* xxx: signal state change. */
		return NULL;
	} else {
		empty = __remove_internal_at(pmp, NULL, indx);
		
		if (empty) {
			__set_state_deleting(pmp);
			bt_page_unlock(pmp);

			__set_state_deleted(mp);
			return pmp;
		} else {
			bt_page_unlock(pmp);

			__set_state_deleted(mp);
			bt_page_put(pmp);
			return NULL;
		}
	}
}

int __bt_delete_leaf(BTREE *t, struct mpage *mp)
{
	struct mpage *pmp;

	pmp = __bt_delete(t, mp);

	while ((mp = pmp) && !IS_ERR(mp)) {

		pmp = __bt_delete(t, mp);
		if (IS_ERR(pmp)) {
			assert(0);
		}

		bt_page_put(mp);
	} 
	return PTR_ERR(mp);
}

int __bt_reorg_delete(BTREE *t, struct mpage *mp)
{
	__set_state_deleting(mp);
	bt_page_unlock(mp);
		
	return __bt_delete_leaf(t, mp);
}

int __bt_reorg_split(BTREE *t, struct mpage *mp)
{
	int err;

	err = __bt_page_shrink(t, mp);
	if (err) {
		assert(0);
		bt_page_unlock(mp);
		return err;
	}

	if (MP_NEED_SPLIT(mp)) { 
		__set_state_splitting(mp);
		bt_page_unlock(mp);

		return __bt_split(t, mp);
	} else {
		__set_state_normal(mp);
		bt_page_unlock(mp);

		__signal_state_change(mp);
		return 0;
	}
}

int __bt_reorg(BTREE *t, struct mpage *mp)
{
	struct mpage *lmp, *rmp, *pmp, *new_root;
	indx_t indx;
	int err;

	bt_page_lock(mp, PAGE_LOCK_EXCL);

	if (MP_ISEMPTY(mp)) {
		return __bt_reorg_delete(t, mp);
	} else {
		return __bt_reorg_split(t, mp);
	}
}

int __bt_split_inline(BTREE *t, struct mpage *mp)
{
	int err;
	pthread_mutex_lock(&reorg_queue_mutex);
	if (mp->state == MP_STATE_INREORGQ) { 
		TAILQ_REMOVE(&reorg_queue_head, mp, reorg_queue_entry);
		__set_state_prereorg(mp);
		pthread_mutex_unlock(&reorg_queue_mutex);

		bt_page_put(mp);

		err = __bt_reorg(t, mp);
		assert(!err);
		return err;
	} else {
		pthread_mutex_unlock(&reorg_queue_mutex);
		
		pthread_mutex_lock(&mp->mutex);
		while (MP_REORGING(mp) || MP_PREREORG(mp))
			pthread_cond_wait(&mp->cond, &mp->mutex);
		pthread_mutex_unlock(&mp->mutex);
		return 0;
	}
}

static int
__bt_put(BTREE *t, const DBT *key, const DBT *val)
{
	struct mpage *mp;
	indx_t indx, indx1;
	bool exact, extended;
	int err;

	mp = __bt_get_leaf_excl(t, key);
	if (IS_ERR(mp)) 
		return PTR_ERR(mp);
	
	while (MP_ISFULL(mp)) {
		assert(mp->npg <= 15);
		bt_page_unlock(mp);

		err = __bt_split_inline(t, mp);			
		assert(err == 0);
	
		bt_page_put(mp);

		mp = __bt_get_leaf_excl(t, key);
		if (IS_ERR(mp)) 
			return PTR_ERR(mp);
	}

	exact = __lookup_leaf(t, mp, key, &indx);
	if (exact) {

		bt_page_unlock(mp);
		bt_page_put(mp);
		return -EEXIST;

		// __remove_leaf_at(mp, key, indx);
	}

	extended = __insert_leaf_at(t, mp, key, val, indx);
	bt_page_unlock(mp);

	if (!extended || !__insert_split_queue(mp))
		bt_page_put(mp);
	return 0;
}

static int
__bt_del(BTREE *t, const DBT *key)
{
	struct mpage *mp;
	indx_t indx;
	bool exact, empty = false;
	int err = 0;

	mp = __bt_get_leaf_excl(t, key);
	if (IS_ERR(mp)) 
		return PTR_ERR(mp);

	exact = __lookup_leaf(t, mp, key, &indx);
	if (exact) {
		empty = __remove_leaf_at(mp, key, indx);
	} else { 
		err = -ENOENT;	
	}
	bt_page_unlock(mp);

	if (!empty || !__insert_delete_queue(mp))
		bt_page_put(mp);
	return err;
}
	
int exito;

void *reorganiser(void *arg)
{
	int err;
	BTREE *t = (BTREE *) arg;
	struct mpage *mp;

	while (1) {
		pthread_mutex_lock(&reorg_queue_mutex);
		while ((mp = reorg_queue_head.tqh_first) == NULL && !exito)
			pthread_cond_wait(&reorg_queue_cond, &reorg_queue_mutex);

		if (mp) {
		   	TAILQ_REMOVE(&reorg_queue_head, mp, reorg_queue_entry);
			__set_state_prereorg(mp);
		}
		pthread_mutex_unlock(&reorg_queue_mutex);

		if (!mp) break;

		err = __bt_reorg(t, mp);
		assert(!err);

		bt_page_put(mp);
	}
}
	
BTREE tt, *t = &tt;

#define MAX_ELE     (1000000)
#define MAX_THREAD  (64) 
#define NORG 16

#define MAX_REGIONS (MAX_ELE/(3*MAX_THREAD))

char bitmap[MAX_ELE/8+1];

int switcher[][3] = { {0,1,2},
                      {0,2,1},
                      {1,0,2},
                      {1,2,0},
                      {2,0,1},
                      {2,1,0} };
int si;

int pt = 0;
int updt = 0;
int lt = 0;
int kill_upd;
static void *looker(
	void *arg)
{
	int err;
	int i = 0;
	unsigned long id  = (unsigned long)arg;
	char key_real[32] = {};
	char b[MAX_REGIONS/8+1];

	char kb[256];
	char vb[256];

	DBT kk, vv;

	memset(key_real, 0, 32);
	memset(b,0,MAX_REGIONS/8+1);
	memset(kb, 0, 256);
	memset(vb, 0, 256);

	while (i < MAX_REGIONS) {
		uint32_t r = random() % MAX_REGIONS;
		uint32_t by=r/8, bi=r%8;
		uint32_t key = r*MAX_THREAD*3+id*3+switcher[si][0];

		if (!(b[by]&(1<<bi))) {

			b[by]|=(1<<bi);

			*(uint32_t *) kb = key;
			kk.data = kb;
			kk.size = 32;


			vv.data = vb;
			vv.size = 250;

			err = __bt_get(t, &kk, &vv);

			if (!err) {
				if (!pt) assert(bitmap[key/8]&(1<<(key%8)));
			} else if (err == -ENOENT) {
				if (!pt) assert(!(bitmap[key/8]&(1<<(key%8))));
			} else {
				fprintf(stderr, "error in lookup\n");
//				exit(1);
			}
			i++;
		}
	}
	
	return NULL;
}

static void *inserter(
	void *arg)
{
	int err;
	int i = 0;
	unsigned long id = (unsigned long)arg;
	char b[MAX_REGIONS/8+1];
	char key_real[32] = {};

	char kb[256];
	char vb[256];

	DBT kk, vv;


	memset(b,0,MAX_REGIONS/8+1);
	memset(key_real, 0, 32);
	memset(kb, 0, 256);
	memset(vb, 0, 256);

	while (i < MAX_REGIONS) {
		uint32_t r = random() % MAX_REGIONS;
		uint32_t by=r/8,bi=r%8;
		uint32_t key = r*MAX_THREAD*3+id*3+switcher[si][1];

		if (!(b[by]&(1<<bi))) {

			b[by]|=(1<<bi);

			*(uint32_t *) kb = key;
			kk.data = kb;
			kk.size = 32;


			*(uint32_t *) vb = key;
			vv.data = vb;
			vv.size = 250;

			err = __bt_put(t, &kk, &vv);
			if (!err) {	

				if (!pt) assert(!(bitmap[key/8]&(1<<(key%8))));
				__sync_fetch_and_or(&bitmap[key/8], 1<<(key%8));

			} else if (err == -EEXIST) {
				if (!pt) assert(bitmap[key/8]&(1<<(key%8)));
			} else {
				fprintf(stderr, "error in insert\n");
			}
			i++;
		}
	}
	
	return NULL;
}

static void *deleter0(
	void *arg)
{
	int err;
	int i=0;
	unsigned long  id = (unsigned long)arg;
	char b[MAX_REGIONS/8+1];
	char key_real[32] = {};

	char kb[256];
	char vb[256];

	DBT kk, vv;


	memset(kb, 0, 256);
	memset(vb, 0, 256);

	memset(b,0,MAX_REGIONS/8+1);
	memset(key_real, 0, 32);

	while (i < MAX_REGIONS) {
		uint32_t r = random() % MAX_REGIONS;
		uint32_t by=r/8,bi=r%8;
		uint32_t key = r*MAX_THREAD*3+id*3+switcher[si][2];

		if (!(b[by]&(1<<bi))) {

			b[by]|=(1<<bi);

			*(uint32_t *) kb = key;
			kk.data = kb;
			kk.size = 32;

			err = __bt_del(t, &kk);
			if (!err) {
				if (!pt) assert(bitmap[key/8]&(1<<(key%8)));
				__sync_fetch_and_and(&bitmap[key/8], ~(1U<<(key%8)));
			} else if (err == -ENOENT) {
				if (!pt) assert(!(bitmap[key/8]&(1<<(key%8))));
			}
			else {
				fprintf(stderr, "error in delete\n");
			//	exit(1);
			}
			i++;
		}
	}

	return NULL;
}

void test(void)
{
	uint32_t k;
	pthread_t lthread[MAX_THREAD],ithread[MAX_THREAD],dthread[MAX_THREAD];

	for (k=0; k<1000; k++)  {
		unsigned long i;
		fprintf(stdout, "START:%d...",k);
		srandom(k);

		for (i=0;i<MAX_THREAD;i++)
			(void)pthread_create(&lthread[i], NULL, looker, (void*)i);

		for (i=0;i<MAX_THREAD;i++)
			(void) pthread_create(&ithread[i], NULL, inserter, (void*)i);


		for (i=0;i<MAX_THREAD;i++)
			(void) pthread_create(&dthread[i], NULL, deleter0, (void*)i);


		for (i=0;i<MAX_THREAD;i++)
			(void)pthread_join(lthread[i], NULL);

		for (i=0;i<MAX_THREAD;i++)
			(void) pthread_join(ithread[i], NULL);

		for (i=0;i<MAX_THREAD;i++)
			(void) pthread_join(dthread[i], NULL);
		
		fprintf(stdout, "DONE.\n");
		si = (si+1)%6;
	}
}

int main()
{
	struct mpage *mp, *mp_md;
	struct dpage *dp;
	pthread_t testers[16];
	pthread_t reorganisers[NORG];
	int i;

	tt.bt_cmp = __bt_defcmp;
	bt_page_init();
	
	mp_md = bt_page_new(1);
	if (IS_ERR(mp_md)) {
		return PTR_ERR(mp_md);
	}
	mp_md->flags = 0;
	MP_SET_METADATA(mp_md);

	mp = bt_page_new(1);
	if (IS_ERR(mp)) {
		return PTR_ERR(mp);
	}

	dp = mp->dp;
	dp->flags = DP_BLEAF;
	dp->lower = DP_HDRLEN;
	dp->upper = mp->npg * PAGE_SIZE;
	mp->flags = 0;
	mp->leftmost = true;
	bt_page_put(mp);

	mp_md->md->root_pgno = mp->pgno;

	bt_page_put(mp_md);

	TAILQ_INIT(&reorg_queue_head);

	pthread_mutex_init(&reorg_queue_mutex, NULL);
	pthread_cond_init(&reorg_queue_cond, NULL);

	for (i = 0; i < NORG; i++) 
		pthread_create(&reorganisers[i], NULL, reorganiser, t);

	test();

	exito = 1;
	pthread_cond_broadcast(&reorg_queue_cond);
	
	for (i = 0; i < NORG; i++) 
		pthread_join(reorganisers[i], NULL);
}
