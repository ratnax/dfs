#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "bt_int.h"

static pthread_mutex_t reorg_qlock;
static pthread_cond_t reorg_qcond;
static struct list_head tree_list;
static pthread_mutex_t tree_list_lock = PTHREAD_MUTEX_INITIALIZER;

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
	if (indx == 0 && DP_ISINTERNAL(dp))
		return (1);

	if (DP_ISLEAF(dp)) {
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

/*
 * @pmp & @gmp are locked on entry.
 * @pmp & @gmp are unlocked and released on failure return.
 */
static struct mpage *
__lookup_parent_nowait(BTREE *t, struct mpage *gmp,
    struct mpage *pmp, const DBT *key, indx_t *indxp)
{
	struct mpage *mp;
	pgno_t pgno;

	pgno = __lookup_internal(t, pmp, key, indxp);
	mp = bt_page_get_nowait(pgno);
	if (!IS_ERR(mp)) 
		return mp;
	bt_page_unlock(pmp);
	bt_page_put(pmp);
	if (gmp) {
		bt_page_unlock(gmp);
		bt_page_put(gmp);
	}
	if (PTR_ERR(mp) != -EAGAIN) 
		return mp;
	mp = bt_page_get(pgno);
	if (IS_ERR(mp)) 
		return mp;
	bt_page_put(mp);
	return ERR_PTR(-EAGAIN);
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

static struct mpage *
__bt_get_root(struct mpage *md)
{
	struct mpage *mp;
	struct dpage *dp = md->dp;

	do {
		mp = bt_page_get_nowait(dp->root_pgno);
		if (!IS_ERR(mp))
			break;
		bt_page_unlock(md);
		if (PTR_ERR(mp) != -EAGAIN) {
			return mp;
		}
		mp = bt_page_get(dp->root_pgno);
		if (IS_ERR(mp)) 
			return mp;
		bt_page_rdlock(md);
		dp = md->dp;
	} while (mp->pgno != dp->root_pgno);

	return mp;
}
			
struct mpage *__bt_get_md(void)
{
	struct mpage *mp;

	mp = bt_page_get(BT_MD_PGNO);
	if (IS_ERR(mp))
		return mp;
	assert(MP_ISMETADATA(mp));
	return mp;
}

/*
 * @mp and @pmp are locked on entry.
 * @mp and @pmp are unlocked and released on failure return.
 * On sucess, rel_on_success determines if pmp lock can be released.
 * @mp and @pmp are unlocked and released on failure return.
 */
static int
__wait_on_reorg(struct mpage *mp, struct mpage *pmp,
    bool rel_on_success)
{
	bool reorging;

	/* Need to check this with pmplock held. */
	if (!MP_REORGING(mp)) {
		if (rel_on_success) {
			bt_page_unlock(pmp);
			bt_page_put(pmp);
		}
		return 0;
	}

	bt_page_unlock(pmp);
	bt_page_put(pmp);

	bt_page_unlock(mp);
	pthread_mutex_lock(&mp->mutex);
	while (MP_REORGING(mp)) 
		pthread_cond_wait(&mp->cond, &mp->mutex);
	pthread_mutex_unlock(&mp->mutex);
	bt_page_put(mp);
	return -EAGAIN;
}

static struct mpage *
__bt_get_leaf_trylocked(BTREE *t, struct txn *tx, const DBT *key, bool excl)
{
	struct mpage *mp, *pmp = NULL;
	indx_t indx;
	int err;

	pmp = __bt_get_md();
	if (IS_ERR(pmp))
		return pmp;

	bt_page_rdlock(pmp);
	mp = __bt_get_root(pmp);
	if (IS_ERR(mp)) {
		bt_page_unlock(pmp);
		bt_page_put(pmp);
		return mp;
	}
	do {
		bt_page_rdlock(mp);
		if (MP_ISLEAF(mp)) {
			if (!excl) {
				bt_page_unlock(pmp);
				bt_page_put(pmp);
				return mp;
			}
			bt_page_unlock(mp);
			bt_page_wrlock(tx, mp);
			if ((err = __wait_on_reorg(mp, pmp, true)))
				return ERR_PTR(err);
			return mp;
		}
		assert(MP_ISINTERNAL(mp));
		if ((err = __wait_on_reorg(mp, pmp, true)))
			return ERR_PTR(err);
		pmp = mp;
		mp = __lookup_parent_nowait(t, NULL, pmp, key, &indx);
	} while (!IS_ERR(mp));
	return mp;
}

static struct mpage *
__bt_get_leaf_locked(BTREE *t, struct txn *tx, const DBT *key, bool excl)
{
	struct mpage *mp;

	do {
		mp = __bt_get_leaf_trylocked(t, tx, key, excl);
	} while (IS_ERR(mp) && PTR_ERR(mp) == -EAGAIN);
	return mp;
}

static struct mpage *
__bt_get_leaf_excl(BTREE *t, struct txn *tx, const DBT *key)
{
	return __bt_get_leaf_locked(t, tx, key, true);
}

static struct mpage *
__bt_get_leaf_shared(BTREE *t, const DBT *key)
{
	return __bt_get_leaf_locked(t, NULL, key, false);
}

/* cmp has to be held by a flag like REORG */
static struct mpage * 
__bt_get_parent_trylocked(BTREE *t, struct txn *tx, struct mpage *cmp,
    DBT *key, indx_t *indxp, bool excl)
{
	struct mpage *mp, *gmp, *pmp;
	pgno_t pgno;
	int err;

	gmp = __bt_get_md();
	if (IS_ERR(gmp))
		return gmp;
	bt_page_rdlock(gmp);
	if (gmp->dp->root_pgno == cmp->pgno) { 
		if (excl) {
			bt_page_unlock(gmp);
			bt_page_wrlock(tx, gmp);
		}
		return gmp;
	} 
	pmp = __bt_get_root(gmp);
	if (IS_ERR(pmp)) {
		bt_page_unlock(gmp);
		bt_page_put(gmp);
		return pmp;
	}
	bt_page_rdlock(pmp);
	mp = __lookup_parent_nowait(t, gmp, pmp, key, indxp);
	while (!IS_ERR(mp)) {
		if (mp->pgno == cmp->pgno) {
			if (!excl) {
				bt_page_unlock(gmp);
				bt_page_put(gmp);
				bt_page_put(mp);
				return pmp;
			}
			bt_page_unlock(pmp);
			bt_page_put(mp);

			bt_page_wrlock(tx, pmp);
			if ((err = __wait_on_reorg(pmp, gmp, true)))
				return ERR_PTR(err);
			pgno = __lookup_internal(t, pmp, key, indxp);
			assert(cmp->pgno == pgno);
			return pmp;
		} 
		bt_page_unlock(gmp);
		bt_page_put(gmp);
		bt_page_rdlock(mp);
		assert(MP_ISINTERNAL(mp));
		if ((err = __wait_on_reorg(mp, pmp, false)))
			return ERR_PTR(err);
		gmp = pmp;
		pmp = mp;	
		mp = __lookup_parent_nowait(t, gmp, pmp, key, indxp);
	}
	return (mp);
}

static struct mpage * 
__bt_get_parent_locked(BTREE *t, struct txn *tx, struct mpage *cmp,
    indx_t *indxp, bool excl)
{
	struct mpage *mp;
	char key_mem[DP_MAX_KSIZE];
	DBT key;
	
	bt_page_rdlock(cmp);
	if (MP_ISLEAF(cmp)) {
		DLEAF *dl = GETDLEAF(cmp->dp, 0);
		memcpy(key_mem, dl->bytes, dl->ksize);
		key.data = key_mem;
		key.size = dl->ksize;
	} else { 	
		DINTERNAL *di;
		if (DP_NXTINDX(cmp->dp) > 1)
			di = GETDINTERNAL(cmp->dp, 1);
		else
			di = GETDINTERNAL(cmp->dp, 0);
		memcpy(key_mem, di->bytes, di->ksize);
		key.data = key_mem;
		key.size = di->ksize;
	}
	bt_page_unlock(cmp); 

	do {
		mp = __bt_get_parent_trylocked(t, tx, cmp, &key, indxp, excl);
	} while (IS_ERR(mp) && PTR_ERR(mp) == -EAGAIN);
	return mp;
}

static struct mpage * 
__bt_get_parent_excl(BTREE *t, struct txn *tx, struct mpage *cmp, indx_t *indxp)
{
	return __bt_get_parent_locked(t, tx, cmp, indxp, true);
}

static struct mpage * 
__bt_get_parent_shared(BTREE *t, struct mpage *cmp, indx_t *indxp)
{
	return __bt_get_parent_locked(t, NULL, cmp, indxp, false);
}

static int
__bt_page_extend(BTREE *t, struct mpage *mp)
{
	struct dpage *dp, *old_dp = mp->dp;
	size_t size = mp->size;
	int i;

	dp = malloc(size + PAGE_SIZE);
	if (!dp)
		return -ENOMEM;
	dp->upper = old_dp->upper + PAGE_SIZE;
	dp->lower = old_dp->lower;
	dp->flags = old_dp->flags;
	memcpy((void *) dp + dp->upper, (void *) old_dp + old_dp->upper, 
			size - old_dp->upper); 
	for (i = 0; i < DP_NXTINDX(old_dp); i++) 
		dp->linp[i] = old_dp->linp[i] + PAGE_SIZE;
	mp->dp = dp;
	mp->size = mp->size + PAGE_SIZE;
	free(old_dp);
	return 0;
}

static int
__bt_page_shrink(BTREE *t, struct mpage *mp)
{
	struct dpage *dp = mp->dp;
	struct dpage *new_dp;
	size_t i, shift;

	if (mp->size == PAGE_SIZE ||
	    dp->upper - dp->lower < (shift = mp->size - PAGE_SIZE)) 
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
	mp->size = PAGE_SIZE; 
	//eprintf("%ld shrink %d %d %ld\n", mp->pgno, new_dp->lower, new_dp->upper, mp->size);
	bt_page_mark_dirty(mp);
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
	bt_page_mark_dirty(mp);
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
	bt_page_mark_dirty(mp);
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
	bt_page_mark_dirty(mp);
	return MP_ISEMPTY(mp);
}

int
bt_get(BTREE *t, const DBT *key, const DBT *val)
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

static void
__signal_state_change(struct mpage *mp)
{
	pthread_mutex_lock(&mp->mutex);
	pthread_cond_broadcast(&mp->cond);
	pthread_mutex_unlock(&mp->mutex);
}

static void
__set_state_deleted(struct txn *tx, struct mpage *mp)
{
	assert(mp->state == MP_STATE_REORGING);
	pthread_mutex_lock(&mp->mutex);
	printf("%d MP_STATE_DELETED\n", mp->pgno);
	mp->state = MP_STATE_DELETED;
	pthread_mutex_unlock(&mp->mutex);
	pthread_cond_broadcast(&mp->cond);

	bt_page_free(tx, mp);
}

static void
__set_state_normal(struct mpage *mp)
{
	assert(mp->state != MP_STATE_DELETED);
	printf("%d MP_STATE_NORMAL\n", mp->pgno);
	mp->state = MP_STATE_NORMAL;
}

static void
__set_state_inreorgq(struct mpage *mp)
{
	assert(mp->state != MP_STATE_DELETED);
	printf("%d MP_STATE_INREORGQ\n", mp->pgno);
	mp->state = MP_STATE_INREORGQ;
}

static void
__set_state_prereorg(struct mpage *mp)
{
	assert(mp->state != MP_STATE_DELETED);
	printf("%d MP_STATE_PREREORG\n", mp->pgno);
	mp->state = MP_STATE_PREREORG;
}

static void
__set_state_reorging(struct mpage *mp)
{
	assert(mp->state != MP_STATE_DELETED);
	printf("%d MP_STATE_REORGING\n", mp->pgno);
	mp->state = MP_STATE_REORGING;
}

static void
__set_state_deleting(struct mpage *mp)
{
	assert(mp->state != MP_STATE_DELETED);
	assert(mp->state != MP_STATE_INREORGQ);

	printf("%d deleting\n", mp->pgno);
	__set_state_reorging(mp);
}

static void
__set_state_splitting(struct mpage *mp)
{
	assert(mp->state != MP_STATE_DELETED);
	printf("%d splitting\n", mp->pgno);
	__set_state_reorging(mp);
}

static bool
__insert_reorg_queue(BTREE *t, struct mpage *mp) 
{
	bool inserted = false;
	assert(mp->pgno);
	pthread_mutex_lock(&reorg_qlock);
	if (MP_NORMAL(mp)) {
		list_add_tail(&mp->reorg_qentry, &t->reorg_qhead);
		__set_state_inreorgq(mp);
		pthread_cond_signal(&reorg_qcond);
		inserted = true;
	}
	pthread_mutex_unlock(&reorg_qlock);
	return inserted;
}

static bool
__insert_split_queue(BTREE *t, struct mpage *mp)
{
	return __insert_reorg_queue(t, mp);
}

static bool
__insert_delete_queue(BTREE *t, struct mpage *mp)
{
	return __insert_reorg_queue(t, mp);
}

static int 
__bt_psplit(struct txn *tx, BTREE *t, struct mpage *mp,
    struct mpage **out_left, struct mpage **out_right, indx_t *out_indx)
{
	void *src;
	DLEAF *dl;
	DINTERNAL *di;
	indx_t full, half, nxt, off, skip, top, used;
	uint32_t nbytes, len, size;

	struct mpage *lmp, *rmp;
	struct dpage *dp = mp->dp;
	struct dpage *ldp;
	struct dpage *rdp;

	/*
	 * Split the data to the left and right pages.  Leave the skip index
	 * open.  Additionally, make some effort not to split on an overflow
	 * key.  This makes internal page processing faster and can save
	 * space as overflow keys used by internal pages are never deleted.
	 */
	len = (dp->lower - DP_HDRLEN + mp->size - dp->upper);
	if (DP_ISLEAF(dp)) {
		len += NDLEAFDBT(DP_MAX_KSIZE, DP_MAX_DSIZE) +
		    sizeof(indx_t) + 1;
	} else { 
		len += NDINTERNAL(DP_MAX_KSIZE) + sizeof(indx_t) + 1;
	}
	half = len / 2 + DP_HDRLEN;
	size = (half + PAGE_MASK) & ~PAGE_MASK;

	lmp = bt_page_new(tx, size);
	assert(lmp);
	rmp = bt_page_new(tx, size);
	assert(rmp);

	bt_page_wrlock(tx, lmp);
	lmp->state = MP_STATE_NORMAL;
	if (lmp->size != size) {
		free(lmp->dp);
		lmp->dp = malloc(size);
		assert(lmp->dp);
		lmp->size = size;
	}
	ldp = lmp->dp;
	ldp->flags = dp->flags & DP_TYPE;
	ldp->lower = DP_HDRLEN;
	ldp->upper = size;

	used = 0;
	for (nxt = off = 0, top = DP_NXTINDX(dp); nxt < top; ++off) {
		switch (dp->flags & DP_TYPE) {
		case DP_INTERNAL:
			src = di = GETDINTERNAL(dp, nxt);
			nbytes = NDINTERNAL(di->ksize);
			break;
		case DP_LEAF:
			src = dl = GETDLEAF(dp, nxt);
			nbytes = NDLEAF(dl);
			break;
		default:
			assert(0);
		}
		if (used + nbytes + sizeof(indx_t) > (size - DP_HDRLEN) ||
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
	*out_indx = off + 1;
	ldp->lower += (off + 1) * sizeof(indx_t);
	bt_page_mark_dirty(lmp);
	bt_page_unlock(lmp);

	bt_page_wrlock(tx, rmp);
	rmp->state = MP_STATE_NORMAL;
	if (rmp->size != size) {
		free(rmp->dp);
		rmp->dp = malloc(size);
		assert(rmp->dp);
		rmp->size = size;
	}

	rdp = rmp->dp;
	rdp->flags = dp->flags & DP_TYPE;
	rdp->lower = DP_HDRLEN;
	rdp->upper = size;

	for (off = 0; nxt < top; ++off) {
		switch (dp->flags & DP_TYPE) {
		case DP_INTERNAL:
			src = di = GETDINTERNAL(dp, nxt);
			nbytes = NDINTERNAL(di->ksize);
			break;
		case DP_LEAF:
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

	bt_page_mark_dirty(rmp);
	bt_page_unlock(rmp);
	assert(ldp->lower <= ldp->upper);
	assert(rdp->lower <= rdp->upper);
	*out_left = lmp;
	*out_right = rmp;
	return 0;
}

static void
__bt_root(BTREE *t, struct txn *tx, struct mpage *mp, struct mpage *pmp,
    struct mpage *lmp, struct mpage *rmp)
{
	struct dpage *ldp, *rdp, *pdp;
	uint32_t nbytes;
	void *dest;
	DLEAF *dl;
	DINTERNAL *di;

	rdp = rmp->dp;
	ldp = lmp->dp;

	bt_page_wrlock(tx, pmp);
	pmp->state = MP_STATE_NORMAL;
	if (pmp->size != PAGE_SIZE) {
		free(pmp->dp);
		pmp->dp = malloc(PAGE_SIZE);
		assert(pmp->dp);
		pmp->size = PAGE_SIZE;
	}
	pdp = pmp->dp;
    
	assert(DP_NXTINDX(ldp));
	assert(DP_NXTINDX(rdp));
	
	nbytes = NDINTERNAL(0);
	pdp->linp[0] = pdp->upper = PAGE_SIZE - nbytes;
	dest = (char *) pdp + pdp->upper;
	__wr_dinternal(dest, NULL, 0, lmp->pgno);
	
	switch (rdp->flags & DP_TYPE) {
	case DP_LEAF:
		dl = GETDLEAF(rdp, 0);
		nbytes = NDINTERNAL(dl->ksize);
		pdp->linp[1] = pdp->upper -= nbytes;
		dest = (char *)pdp + pdp->upper;
		__wr_dinternal(dest, dl->bytes, dl->ksize, rmp->pgno);
		break;
	case DP_INTERNAL:
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
	pdp->flags |= DP_INTERNAL;

	bt_page_mark_dirty(pmp);
	bt_page_unlock(pmp);
}

static bool 
__bt_page(BTREE *t, struct mpage *mp, struct mpage *pmp, indx_t indx,
    struct mpage *lmp, struct mpage *rmp)
{
	struct dpage *rdp, *ldp, *pdp, *old_pdp;
	void *dest;
	uint32_t nbytes;
	DLEAF *dl;
	DINTERNAL *di;
	int err;
	indx_t nxtindx;
	int i;

	rdp = rmp->dp;
	ldp = lmp->dp;
	old_pdp = pdp = pmp->dp;

	switch (rdp->flags & DP_TYPE) {
	case DP_INTERNAL:
		di = GETDINTERNAL(rdp, 0);
		nbytes = NDINTERNAL(di->ksize);
		break;
	case DP_LEAF:
		dl = GETDLEAF(rdp, 0);
		nbytes = NDINTERNAL(dl->ksize);
		break;
	default:
		assert(0);
	}

	/* Split the parent page if necessary or shift the indices. */
	if (pdp->upper - pdp->lower < nbytes + sizeof(indx_t)) {
		err = __bt_page_extend(t, pmp);
		assert(!err);

		pdp = pmp->dp;
	}	
	nxtindx = DP_NXTINDX(pdp);
	memmove(pdp->linp + indx + 1, pdp->linp + indx,
			    (nxtindx - indx) * sizeof(indx_t));
	pdp->lower += sizeof(indx_t);

	/* Insert the key into the parent page. */
	switch (rdp->flags & DP_TYPE) {
	case DP_INTERNAL:
		pdp->linp[indx + 1] = pdp->upper -= nbytes;
		dest = (char *) pdp + pdp->linp[indx + 1];
		__wr_dinternal(dest, di->bytes, di->ksize, rmp->pgno);
		break;
	case DP_LEAF:
		pdp->linp[indx + 1] = pdp->upper -= nbytes;
		dest = (char *) pdp + pdp->linp[indx + 1];
		__wr_dinternal(dest, dl->bytes, dl->ksize, rmp->pgno);
		break;
	default:
		assert(0);	
	}
	di = GETDINTERNAL(pdp, indx);
	di->pgno = lmp->pgno;

	bt_page_mark_dirty(pmp);
	//eprintf("<%ld %ld %ld>\n", pmp->pgno, lmp->pgno, rmp->pgno);
	return pdp != old_pdp;
}

static int __bt_reorg_split(struct txn *tx, BTREE *t, struct mpage *mp);

int
bt_put(struct txn *tx, BTREE *t, const DBT *key, const DBT *val)
{
	struct mpage *mp;
	indx_t indx, indx1;
	bool exact, extended;
	int err;

	mp = __bt_get_leaf_excl(t, tx, key);
	if (IS_ERR(mp)) 
		return PTR_ERR(mp);
	
	while (MP_ISFULL(mp)) {
		assert(mp->size <= 16 << PAGE_SHFT);
		if (MP_INREORGQ(mp)) {
			list_del(&mp->reorg_qentry);
			__set_state_prereorg(mp);
		}
		pthread_mutex_unlock(&reorg_qlock);
		err = __bt_reorg_split(tx, t, mp);			
		assert(err == 0);
		bt_page_put(mp);
		mp = __bt_get_leaf_excl(t, tx, key);
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
	if ((extended = __insert_leaf_at(t, mp, key, val, indx)))
		extended = __insert_split_queue(t, mp);

	err = bt_txn_log_ins_leaf(tx, mp, indx); 
	assert(!err);
	bt_page_unlock(mp);

	if (!extended) bt_page_put(mp);
	return 0;
}

int
bt_del(struct txn *tx, BTREE *t, const DBT *key)
{
	struct mpage *mp;
	indx_t indx;
	bool exact, empty = false;
	int err = 0;

	mp = __bt_get_leaf_excl(t, tx, key);
	if (IS_ERR(mp)) 
		return PTR_ERR(mp);
	exact = __lookup_leaf(t, mp, key, &indx);
	if (exact) {
		err = bt_txn_log_del_leaf(tx, mp, indx); 
		assert(!err);
		if ((empty = __remove_leaf_at(mp, key, indx)))
			empty = __insert_delete_queue(t, mp);
	} else { 
		err = -ENOENT;	
	}
	bt_page_unlock(mp);

	if (!empty) bt_page_put(mp);
	return err;
}

static int
__bt_split(struct txn *tx, BTREE *t, struct mpage *mp)
{
	struct mpage *lmp, *rmp, *pmp, *new_root;
	indx_t indx, splt_indx;
	bool lmp_need_split = false;
	bool rmp_need_split = false;
	bool pmp_need_split = false;
	int err;

	err = __bt_psplit(tx, t, mp, &lmp, &rmp, &splt_indx);
	assert(!err);

	new_root = NULL;
	pmp = __bt_get_parent_excl(t, tx, mp, &indx);
	if (IS_ERR(pmp)) {
		assert(0);
		return PTR_ERR(pmp);
	}
	if (MP_ISMETADATA(pmp)) {
		assert(pmp->pgno == BT_MD_PGNO);
		bt_page_unlock(pmp);
		new_root = bt_page_new(tx, PAGE_SIZE);
		if (IS_ERR(new_root)) {
			assert(0);
			return PTR_ERR(new_root);
		}
		__bt_root(t, tx, mp, new_root, lmp, rmp);
		bt_page_wrlock(tx, pmp);
		pmp->dp->root_pgno = new_root->pgno;
		bt_page_mark_dirty(pmp);

		err = bt_txn_log_newroot(tx, new_root, mp, lmp, rmp, pmp,
		    splt_indx); 
		assert(!err);
	} else {
		while (MP_ISFULL(pmp)) {

			pthread_mutex_lock(&reorg_qlock);
			if (MP_INREORGQ(pmp)) {
				list_del(&pmp->reorg_qentry);
				__set_state_prereorg(pmp);
			}
			pthread_mutex_unlock(&reorg_qlock);
			err = __bt_reorg_split(tx, t, pmp);
			assert(err == 0);
			bt_page_put(pmp);
			pmp = __bt_get_parent_excl(t, tx, mp, &indx);
			if (IS_ERR(pmp)) 
				return PTR_ERR(pmp);
		}
		if ((pmp_need_split = __bt_page(t, mp, pmp, indx, lmp, rmp))) 
			pmp_need_split = __insert_split_queue(t, pmp);
	    
		err = bt_txn_log_split(tx, pmp, mp, lmp, rmp, indx, splt_indx); 
		assert(!err);
	}
	
	if ((lmp_need_split = MP_NEED_SPLIT(lmp)))
		lmp_need_split = __insert_split_queue(t, lmp);
	if ((rmp_need_split = MP_NEED_SPLIT(rmp)))
		rmp_need_split = __insert_split_queue(t, rmp);
	
	bt_page_unlock(pmp);
	__set_state_deleted(tx, mp);

	if (new_root) bt_page_put(new_root);
	if (!lmp_need_split) bt_page_put(lmp);
	if (!rmp_need_split) bt_page_put(rmp);
	if (!pmp_need_split) bt_page_put(pmp);
	return 0;
}

static struct mpage *
__bt_delete(struct txn *tx, BTREE *t, struct mpage *mp)
{
	struct mpage *pmp;
	struct dpage *dp;
	indx_t indx;
	int i;
	bool empty;
	int err;

	pmp = __bt_get_parent_excl(t, tx, mp, &indx);
	if (IS_ERR(pmp))
		return pmp;
	if (MP_ISMETADATA(pmp)) {
		bt_page_unlock(pmp);
		bt_page_put(pmp);
		bt_page_wrlock(tx, mp);
		dp = mp->dp;
		dp->flags &= ~DP_INTERNAL;
		dp->flags |= DP_LEAF;
		dp->lower = DP_HDRLEN;
		dp->upper = mp->size; /* xxx: extended ? */
		bt_page_mark_dirty(mp);
		bt_page_unlock(mp);
		__set_state_normal(mp);
		assert(0);
		/* xxx: signal state change. */
		return NULL;
	} else {
		err = bt_txn_log_del_internal(tx, pmp, indx);
		assert(!err);
		empty = __remove_internal_at(pmp, NULL, indx);
		if (empty) {
			pthread_mutex_lock(&reorg_qlock);
			if (MP_INREORGQ(pmp)) {
				list_del(&pmp->reorg_qentry);
				__set_state_prereorg(pmp);
			}
			pthread_mutex_unlock(&reorg_qlock);

			__set_state_deleting(pmp);
			bt_page_unlock(pmp);
			__set_state_deleted(tx, mp);
			return pmp;
		} else {
			bt_page_unlock(pmp);
			bt_page_put(pmp);
			__set_state_deleted(tx, mp);
			return NULL;
		}
	}
}

static int
__bt_delete_leaf(struct txn *tx, BTREE *t, struct mpage *mp)
{
	struct mpage *pmp;

	pmp = __bt_delete(tx, t, mp);
	while ((mp = pmp) && !IS_ERR(mp)) {
		pmp = __bt_delete(tx, t, mp);
		if (IS_ERR(pmp)) {
			assert(0);
		}
		bt_page_put(mp);
	} 
	return PTR_ERR(mp);
}

static int
__bt_reorg_delete(struct txn *tx, BTREE *t, struct mpage *mp)
{
	__set_state_deleting(mp);
	bt_page_unlock(mp);
	return __bt_delete_leaf(tx, t, mp);
}

static int
__bt_reorg_split(struct txn *tx, BTREE *t, struct mpage *mp)
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
		return __bt_split(tx, t, mp);
	} else {
		__set_state_normal(mp);
		bt_page_unlock(mp);
		__signal_state_change(mp);
		return 0;
	}
}

static int
__bt_reorg(struct txn *tx, BTREE *t, struct mpage *mp)
{
	struct mpage *lmp, *rmp, *pmp, *new_root;
	indx_t indx;
	int err;

	bt_page_wrlock(tx, mp);
	if (!MP_PREREORG(mp)) {
		bt_page_unlock(mp);
		return 0;
	}
	if (MP_ISEMPTY(mp)) {
		if (MP_ISLEAF(mp))
			return __bt_reorg_delete(tx, t, mp);
		else {
			__set_state_normal(mp);
			bt_page_unlock(mp);
			__signal_state_change(mp);
		}

	} else {
		return __bt_reorg_split(tx, t, mp);
	}
}

static int exito;

static void *reorganiser(void *arg)
{
	int err;
	struct mpage *mp;
	struct txn *tx;
	BTREE *t;

	while (1) {
		pthread_mutex_lock(&reorg_qlock);
		while (1) {
			mp = NULL;
			pthread_mutex_lock(&tree_list_lock);
			list_for_each_entry(t, &tree_list, list) {
				if (list_empty(&t->reorg_qhead))
					continue;
		    		mp = list_first_entry(&t->reorg_qhead,
				    struct mpage, reorg_qentry);

				list_del(&mp->reorg_qentry);
				__set_state_prereorg(mp);
				break;
			}
			pthread_mutex_unlock(&tree_list_lock);
			if (!mp && !exito)
				pthread_cond_wait(&reorg_qcond, &reorg_qlock);
			else
				break;
		}
		pthread_mutex_unlock(&reorg_qlock);
		if (!mp) 
			break;
		tx = txn_alloc(true);
		assert(!IS_ERR(tx));
		
		err = __bt_reorg(tx, t, mp);
		assert(!err);
		bt_page_put(mp);
		err = txn_commit(tx, true);
		assert(!err);
		// txn_free(tx);
	}
}
	
int
bt_mkfs(int fd, pgno_t root_pgno)
{
	struct dpage *dp;
	ssize_t b;
	int ret;

	if (!(dp = calloc(PAGE_SIZE, 1)))
		return -ENOMEM;

	dp->flags = DP_LEAF;
	dp->lower = DP_HDRLEN;
	dp->upper = PAGE_SIZE;
	if (PAGE_SIZE != (b = pwrite(fd, dp, PAGE_SIZE,
	    root_pgno << PAGE_SHFT))) {
		free(dp);
		return -EIO;
	}

	dp->flags = DP_METADATA;
	dp->root_pgno = root_pgno;
	if (PAGE_SIZE != (b = pwrite(fd, dp, PAGE_SIZE,
	    BT_MD_PGNO << PAGE_SHFT))) {
		free(dp);
		return -EIO;
	}
	free(dp);
	return 0;
}

static void
print_subtree(struct mpage *mp, int level)
{
	int i;
	struct dpage *dp = mp->dp;

	// assert(bt_page_valid(mp));
	if (MP_ISINTERNAL(mp)) {
		for (i = 0; i < DP_NXTINDX(dp); i++) {
			DINTERNAL *di = GETDINTERNAL(dp, i);
			struct mpage *_mp;

			_mp = bt_page_get(di->pgno);
			print_subtree(_mp, level + 1);
			bt_page_put(_mp);
		}
		return;
		eprintf("INTERNAL: %lu@%d\n", (uint64_t) mp->pgno, level);
		for (i = 0; i < DP_NXTINDX(dp); i++) {
			DINTERNAL *di = GETDINTERNAL(dp, i);
			eprintf("%02x", ((unsigned char *) di->bytes)[0]);
			eprintf("%02x", ((unsigned char *) di->bytes)[1]);
			eprintf("%02x", ((unsigned char *) di->bytes)[2]);
			eprintf("%02x ", ((unsigned char *) di->bytes)[3]);
		}
		eprintf("\n");
		for (i = 0; i < DP_NXTINDX(dp); i++) {
			DINTERNAL *di = GETDINTERNAL(dp, i);
			eprintf("%8lu ", (uint64_t) di->pgno); 
		}
		eprintf("\n");
	} else {
		return;
		eprintf("LEAF: %lu@%d\n", (uint64_t) mp->pgno, level);
		for (i = 0; i < DP_NXTINDX(dp); i++) {
			DLEAF *di = GETDLEAF(dp, i);
			eprintf("%02x", ((unsigned char *) di->bytes)[0]);
			eprintf("%02x", ((unsigned char *) di->bytes)[1]);
			eprintf("%02x", ((unsigned char *) di->bytes)[2]);
			eprintf("%02x ", ((unsigned char *) di->bytes)[3]);
		}
		eprintf("\n");
	}
}

void print_tree(BTREE *t)
{
	struct mpage *md, *mp;
	int err;

	md = __bt_get_md();
	assert(md && !IS_ERR(md));
	mp = bt_page_get(md->dp->root_pgno);
	assert(mp && !IS_ERR(mp));
	print_subtree(mp, 0);
	bt_page_put(mp);
	bt_page_put(md);
	//check_pages();
}

BTREE *
bt_alloc(void)
{
	BTREE *t;

	if (!(t = malloc(sizeof(BTREE))))
		return ERR_PTR(-ENOMEM);
	t->bt_cmp = __bt_defcmp;
	INIT_LIST_HEAD(&t->reorg_qhead);
	pthread_mutex_lock(&tree_list_lock);
	list_add_tail(&t->list, &tree_list);
	pthread_mutex_unlock(&tree_list_lock);
	return t;
}

#define NORG 16
static pthread_t reorganisers[NORG];

void bt_system_exit(void)
{
	int i;

	pthread_mutex_lock(&reorg_qlock);
	exito = 1;
	pthread_cond_broadcast(&reorg_qcond);
	pthread_mutex_unlock(&reorg_qlock);
	for (i = 0; i < NORG; i++) 
		pthread_join(reorganisers[i], NULL);
	bt_page_system_exit();
}

int bt_system_init(int fd)
{
	int i, ret;

	bt_page_system_init();

	pthread_mutex_init(&reorg_qlock, NULL);
	pthread_cond_init(&reorg_qcond, NULL);
	INIT_LIST_HEAD(&tree_list);

	for (i = 0; i < NORG; i++) {
		if ((ret = pthread_create(&reorganisers[i], NULL,
		    reorganiser, NULL)))
			return ret;
	}
	return 0;
}
