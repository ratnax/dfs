#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "mp_mem.h"

static TAILQ_HEAD(spl_queue, mpage) splq_head;
static TAILQ_HEAD(del_queue, mpage) delq_head;

static pthread_mutex_t splq_mutex;
static pthread_mutex_t delq_mutex;

static pthread_cond_t splq_cond;
static pthread_cond_t delq_cond;


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
	if (indx == 0 && (dp->flags & DP_BINTERNAL))
		return (1);

//	if (indx == 0 && (dp->flags & DP_BINTERNAL))
//		return (1);


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

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/*
 * __BT_DEFCMP -- Default comparison routine.
 *
 * Parameters:
 *	a:	DBT #1
 *	b: 	DBT #2
 *
 * Returns:
 *	< 0 if a is < b
 *	= 0 if a is = b
 *	> 0 if a is > b
 */
static int
__bt_defcmp(const DBT *a, const DBT *b)
{
	register size_t len;
	register unsigned char *p1, *p2;


	if (a->size == 0 && b->size == 0) return 0;
	if (b->size == 0) return 1;
	if (a->size == 0) return -1;

	return ((long) (*(uint32_t *) a->data)) - ((long)(*(uint32_t *) b->data));

	/*
	 * XXX
	 * If a size_t doesn't fit in an int, this routine can lose.
	 * What we need is a integral type which is guaranteed to be
	 * larger than a size_t, and there is no such thing.
	 */
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

	assert(DP_NXTINDX(p_mp->dp));
	pgno = __lookup_internal(t, p_mp, key, indxp);
	if ((mp = bt_page_get_nowait(pgno))) {

		if (*indxp == 0 && p_mp->leftmost)
			mp->leftmost = true;
		else
			mp->leftmost = false;

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

void __check_links(struct mpage *pmp, struct mpage *lmp, struct mpage *rmp, int indx)
{
	DINTERNAL *pdi = GETDINTERNAL(pmp->dp, indx);
	
	return;

	if (lmp->dp->flags & DP_BLEAF) {
		struct dpage *ldp = lmp->dp;
		DLEAF *dl = GETDLEAF(ldp, 0);

		if (pdi->ksize) 
			assert(*(unsigned int *)(dl->bytes) >= *(unsigned int *) pdi->bytes);
		else
			assert(*(unsigned int *)(dl->bytes) >= 0);
	} else {
		struct dpage *ldp = lmp->dp;
		DINTERNAL *di = GETDINTERNAL(ldp, 0);

		if (di->ksize) {
			if (pdi->ksize)
				assert(*(unsigned int *)(di->bytes) == *(unsigned int *) pdi->bytes);
			else
				assert(*(unsigned int *)(di->bytes) >= 0);
		} else
			assert(pdi->ksize == 0);
	}

	if (!rmp) return;

	pdi = GETDINTERNAL(pmp->dp, indx+1);

	if (rmp->dp->flags & DP_BLEAF) {
		struct dpage *rdp = rmp->dp;
		DLEAF *dl = GETDLEAF(rdp, 0);

		assert(*(unsigned int *)(dl->bytes) >= *(unsigned int *) pdi->bytes);
	} else {
		struct dpage *rdp = rmp->dp;
		DINTERNAL *di = GETDINTERNAL(rdp, 0);

		assert(di->ksize);
		assert(pdi->ksize);
		assert(*(unsigned int *)(di->bytes) == *(unsigned int *) pdi->bytes);
	}

}

void validate(struct mpage *mp)
{
	int i;
	return;
	if (mp->dp->flags & DP_BLEAF) return;
	for (i = 0; i < DP_NXTINDX(mp->dp); i++) {
		DINTERNAL *di = GETDINTERNAL(mp->dp, i);
		bt_page_put(bt_page_get(di->pgno));
	}
}

void __check_order(struct mpage *mp)
{
	struct dpage *dp = mp->dp;
	unsigned int prev = 0, k;
	int i;
	return;
	
//	if (dp->flags & DP_BINTERNAL) 
//		return;
	
//	return;
	for (i = (dp->flags & DP_BLEAF) ? 0 : 1; i < DP_NXTINDX(dp); i++) {

		if (dp->flags & DP_BLEAF) {
			DLEAF *dl = (DLEAF *) (mp->p + dp->linp[i]);
			k = *(unsigned int *) dl->bytes;
		} else {
			DINTERNAL *di = (DINTERNAL *) (mp->p + dp->linp[i]);
			if (di->ksize == 0)
				k = 0;
			else
				k = *(unsigned int *) di->bytes;
		}

		assert(prev <= k);
		prev = k;
	}
}
			

struct mpage *__get_md_page(void)
{
	struct mpage *mp;
	mp = bt_page_get(P_MDPGNO);
	if (IS_ERR(mp))
		return mp;

	mp->flags |= MP_METADATA;
	return mp;
}

static struct mpage * __bt_get_leaf(BTREE *t, const DBT *key, int excl)
{
	struct mpage *mp, *p_mp = NULL;
	indx_t indx;

	do {
		p_mp = __get_md_page();
		if (IS_ERR(p_mp))
			return p_mp;

		bt_page_lock(p_mp, PAGE_LOCK_SHARED);

		//printf("%d ", p_mp->pgno);
//		fflush(stdout);
		mp = __bt_get_root(p_mp);
		if (IS_ERR(mp)) {
			bt_page_unlock(p_mp);
			bt_page_put(p_mp);
			return mp;
		}
		while (!IS_ERR(mp)) {

			printf("%d ", mp->pgno);
//			fflush(stdout);

			if (mp->dp->flags & DP_BINTERNAL) {
				bt_page_lock(mp, PAGE_LOCK_SHARED);
				assert(!(mp->flags & MP_DELETED));

				if (mp->flags & MP_SPLITTING ||
					mp->flags & MP_DELETING) {

					bt_page_unlock(mp);
					bt_page_unlock(p_mp);

					pthread_mutex_lock(&mp->mutex);
					while (mp->flags & MP_SPLITTING ||
						mp->flags & MP_DELETING) 
						pthread_cond_wait(&mp->cond, &mp->mutex);
					pthread_mutex_unlock(&mp->mutex);

					bt_page_put(mp);
					mp = ERR_PTR(EAGAIN);
					break;
				}
			} else {

				if (excl) {
					bt_page_lock(mp, PAGE_LOCK_EXCL);

					assert(!(mp->flags & MP_DELETED));

					if (mp->flags & MP_SPLITTING ||
						mp->flags & MP_DELETING) {

						bt_page_unlock(mp);
						bt_page_unlock(p_mp);

						pthread_mutex_lock(&mp->mutex);
						while (mp->flags & MP_SPLITTING ||
							mp->flags & MP_DELETING) 
							pthread_cond_wait(&mp->cond, &mp->mutex);
						pthread_mutex_unlock(&mp->mutex);

						bt_page_put(mp);
						mp = ERR_PTR(EAGAIN);
						break;
					}
				} else {
					bt_page_lock(mp, PAGE_LOCK_SHARED);
				}
			}

			bt_page_unlock(p_mp);
			bt_page_put(p_mp);

			if (mp->dp->flags & DP_BLEAF) {
				printf("\n");
				//assert(!(mp->flags & MP_DELETED));
				return mp;
			}

			p_mp = mp;
			mp = __lookup_parent_nowait(t, NULL, p_mp, key, &indx);
		}

		bt_page_put(p_mp);
		printf("\n");
	} while (PTR_ERR(mp) == EAGAIN);

	return mp;
}

static struct mpage *__bt_get_leaf_excl(BTREE *t, const DBT *key)
{
	return __bt_get_leaf(t, key, true);
}

static struct mpage *__bt_get_leaf_shared(BTREE *t, const DBT *key)
{
	return __bt_get_leaf(t, key, false);
}

static struct mpage * 
__get_parent_locked(BTREE *t, struct mpage *c_mp, indx_t *indxp, bool excl)
{
	struct mpage *mp, *g_mp, *p_mp = NULL;
	char key_mem[DP_MAX_KSIZE];
	DBT key;
	pgno_t pgno;
	
	bt_page_lock(c_mp, PAGE_LOCK_SHARED); 
	if (c_mp->dp->flags & DP_BLEAF) {
		DLEAF *dl = GETDLEAF(c_mp->dp, 0);
		memcpy(key_mem, dl->bytes, dl->ksize);
		key.data = key_mem;
		key.size = dl->ksize;
//		assert(dl->ksize && dl->ksize <= DP_MAX_KSIZE);
	} else { 	
		DINTERNAL *di = GETDINTERNAL(c_mp->dp, 0);
		memcpy(key_mem, di->bytes, di->ksize);
		key.data = key_mem;
		key.size = di->ksize;
//		assert(di->ksize && di->ksize <= DP_MAX_KSIZE);
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
				assert(!(p_mp->flags & MP_DELETED));
				if (excl) {
					bt_page_unlock(p_mp);
					bt_page_put(mp);
					bt_page_lock(p_mp, PAGE_LOCK_EXCL);
					if (p_mp->flags & MP_SPLITTING ||
						p_mp->flags & MP_DELETING) {

						bt_page_unlock(g_mp);
						bt_page_unlock(p_mp);

						pthread_mutex_lock(&p_mp->mutex);
						while (p_mp->flags & MP_SPLITTING ||
							p_mp->flags & MP_DELETING) 
							pthread_cond_wait(&p_mp->cond, &p_mp->mutex);
						pthread_mutex_unlock(&p_mp->mutex);
						mp = ERR_PTR(EAGAIN);
						break;
					}
				} else {
					bt_page_put(mp);
				}

				bt_page_unlock(g_mp);
				bt_page_put(g_mp);

				pgno = __lookup_internal(t, p_mp, &key, indxp);
				assert(pgno == c_mp->pgno);
				assert(*indxp < DP_NXTINDX(p_mp->dp));
				DINTERNAL *di = GETDINTERNAL(p_mp->dp, *indxp);
				assert(di->pgno == pgno);

				assert(!(p_mp->flags & MP_DELETED));
				return p_mp;
			} 

			bt_page_unlock(g_mp);
			bt_page_put(g_mp);

			bt_page_lock(mp, PAGE_LOCK_SHARED);

			__check_links(p_mp, mp, NULL, *indxp);

			assert(!(mp->dp->flags & DP_BLEAF));
			if (mp->flags & MP_SPLITTING ||
				mp->flags & MP_DELETING) {

				bt_page_unlock(p_mp);
				bt_page_unlock(mp);
				g_mp = NULL;

				pthread_mutex_lock(&mp->mutex);
				while (mp->flags & MP_SPLITTING ||
						mp->flags & MP_DELETING) 
					pthread_cond_wait(&mp->cond, &mp->mutex);
				pthread_mutex_unlock(&mp->mutex);

				bt_page_put(mp);
				mp = ERR_PTR(EAGAIN);
				break;
			}

			g_mp = p_mp;
			p_mp = mp;	
			mp = __lookup_parent_nowait(t, g_mp, p_mp, &key, indxp);
		}

		if (p_mp) {
			bt_page_put(p_mp);
		}	
		if (g_mp) {
			bt_page_put(g_mp);
		}
	} while (PTR_ERR(mp) == EAGAIN);

	return mp;
}

static struct mpage * 
__get_parent_locked_excl(BTREE *t, struct mpage *c_mp, indx_t *indxp)
{
	return __get_parent_locked(t, c_mp, indxp, true);
}

static struct mpage * 
__get_parent_locked_shared(BTREE *t, struct mpage *c_mp, indx_t *indxp)
{
	return __get_parent_locked(t, c_mp, indxp, false);
}

static int __bt_page_extend(BTREE *t, struct mpage *mp)
{
	struct dpage *dp, *old_dp = mp->dp;
	size_t size = PAGE_SIZE * mp->npg;
	int i;

	printf("Extending: %d\n", mp->pgno);
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

	pthread_mutex_lock(&splq_mutex);
	if (!(mp->flags & MP_INSPLQ)) {
		// printf("QQQQ splitting :%ld\n", mp->pgno);
		TAILQ_INSERT_TAIL(&splq_head, mp, spl_entries);
		mp->flags |= MP_INSPLQ;
		bt_page_ref(mp);
		pthread_cond_signal(&splq_cond);
		assert(!(mp->flags & MP_DELETED));
	}
	pthread_mutex_unlock(&splq_mutex);
	free(old_dp);
	__check_order(mp);
	return 0;
}

static int __bt_page_shrink(BTREE *t, struct mpage *mp)
{
	struct dpage *dp = NULL, *old_dp = mp->dp;
	size_t size = PAGE_SIZE * mp->npg; 
	int i;

	assert(mp->npg > 1);
	assert(DP_NXTINDX(old_dp));

	dp = malloc(size);
	if (!dp)
		return -ENOMEM;

	assert(old_dp->upper >= size - PAGE_SIZE);
	dp->upper = old_dp->upper - (size - PAGE_SIZE);
	dp->lower = old_dp->lower;
	dp->flags = old_dp->flags;

	memcpy((void *) dp + dp->upper, (void *) old_dp + old_dp->upper, 
			size - old_dp->upper);  

	for (i = 0; i < DP_NXTINDX(old_dp); i++) 
		dp->linp[i] = old_dp->linp[i] - (size - PAGE_SIZE);

	mp->dp = dp;
	mp->npg = 1; 
	free(old_dp);
	__check_order(mp);
	return 0;
}

static void
__insert_leaf_at(BTREE *t, struct mpage *mp, const DBT *key, const DBT *val,
				indx_t indx)
{
	struct dpage *dp = mp->dp;
	size_t nbytes;
	indx_t nxtindx;

	assert(!(mp->flags & MP_DELETED));
	nbytes = NDLEAFDBT(key->size, val->size);

	printf("pgno: %d upper: %d lower: %d nbytes: %d\n",
			mp->pgno, dp->upper, dp->lower, nbytes);
	if (dp->upper - dp->lower < nbytes + sizeof(indx_t)) {
		__bt_page_extend(t, mp);
		dp = mp->dp;
	}

	if (indx < (nxtindx = DP_NXTINDX(dp))) {
		memmove(dp->linp + indx + 1, dp->linp + indx,
		    (nxtindx - indx) * sizeof(indx_t));
	}
	assert(indx < ((mp->npg * PAGE_SIZE) -  dp->lower) / sizeof(indx_t));

	dp->lower += sizeof(indx_t);
	dp->linp[indx] = dp->upper -= nbytes;

	__wr_dleaf((void *) dp + dp->upper, key, val);
	__check_order(mp);
}

static void
__remove_leaf_at(struct mpage *mp, DBT *key, indx_t indx)
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
	__check_order(mp);
}

static void
__remove_internal_at(struct mpage *mp, DBT *key, indx_t indx)
{
	DINTERNAL *di;
	indx_t cnt, *ip, offset;
	uint32_t nbytes;
	void *to;
	char *from;
	struct dpage *dp = mp->dp;

	/*
	if (indx == 0 && DP_NXTINDX(dp) > 1) {
		DINTERNAL *next_di;

		di = GETDINTERNAL(dp, 0);
		next_di = GETDINTERNAL(dp, 1);
		
		di->pgno = next_di->pgno;
		indx = 1;
	}
	*/
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


	__check_order(mp);

#if 0
	if (DP_NXTINDX(dp) && mp->flags & MP_LEFTMOST && indx == 0) {
		di = GETDINTERNAL(dp, 0);

		nbytes = di->ksize;
		from = (char *) dp + dp->upper;
		to = from + nbytes;

		memmove(to, from, (char *) di->bytes - from); 
		dp->upper += nbytes;

		offset = dp->linp[0];
		for (cnt = 0; cnt < DP_NXTINDX(dp); cnt++)
			if (dp->linp[cnt] <= offset)
				dp->linp[cnt] += nbytes;

		di = GETDINTERNAL(dp, 0);
		di->ksize = 0;
		fprintf(stderr, "here:%d\n", mp->pgno);
		__check_order(mp);
	}
#endif
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

pthread_mutex_t _m = PTHREAD_MUTEX_INITIALIZER;
static int
__bt_put(BTREE *t, const DBT *key, const DBT *val)
{
	struct mpage *mp;
	indx_t indx, indx1;
	bool exact;

	do {
		mp = __bt_get_leaf_excl(t, key);
		if (IS_ERR(mp)) 
			return PTR_ERR(mp);

		if (mp->npg == 15) {
			bt_page_unlock(mp);
			bt_page_put(mp);
		//	pthread_mutex_unlock(&_m);
			sleep(1);
		//	pthread_mutex_lock(&_m);
		} else 
			break;
	} while (1);

	assert(!(mp->flags & MP_DELETED));
	exact = __lookup_leaf(t, mp, key, &indx);
	if (exact) {

		bt_page_unlock(mp);
		bt_page_put(mp);
		return -EEXIST;

		// __remove_leaf_at(mp, key, indx);
	}

	__insert_leaf_at(t, mp, key, val, indx);

//	assert(__lookup_leaf(t, mp, key, &indx1));
//	assert(indx == indx1);
	
	bt_page_unlock(mp);
	bt_page_put(mp);
	return 0;
}

static int
__bt_del(BTREE *t, const DBT *key)
{
	struct mpage *mp;
	indx_t indx;
	bool exact;
	int err = 0;

	mp = __bt_get_leaf_excl(t, key);
	if (IS_ERR(mp)) 
		return PTR_ERR(mp);

	assert(!(mp->flags & MP_DELETED));
	exact = __lookup_leaf(t, mp, key, &indx);
	if (exact) {

/*
		DLEAF *dl = GETDLEAF(mp->dp, indx);
		
		assert(dl->ksize == key->size);
		assert(!memcmp(key->data, dl->bytes, key->size));

*/
		__remove_leaf_at(mp, key, indx);

//		assert(!__lookup_leaf(t, mp, key, &indx));

		if (DP_NXTINDX(mp->dp) == 0) {

/*
			pthread_mutex_lock(&splq_mutex);
			if ((mp->flags & MP_INSPLQ)) {
				TAILQ_REMOVE(&splq_head, mp, spl_entries);
				mp->flags &= ~MP_INSPLQ;
			} 
			pthread_mutex_unlock(&splq_mutex);
				
*/		
			pthread_mutex_lock(&delq_mutex);
			if (!(mp->flags & MP_INDELQ)) {
				TAILQ_INSERT_TAIL(&delq_head, mp, del_entries);
				mp->flags |= MP_INDELQ;
				bt_page_ref(mp);
				pthread_cond_signal(&delq_cond);
				assert(!(mp->flags & MP_DELETED));
			}
			pthread_mutex_unlock(&delq_mutex);
		}	
	}
	else { 
		err = -ENOENT;	
	}

	bt_page_unlock(mp);
	bt_page_put(mp);
	return err;
}


static void  
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
		assert(&ldp->linp[off+1] <= (char *)ldp + ldp->upper);

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
		assert(&rdp->linp[off+1] <= (char *)rdp + rdp->upper);
	}
	rdp->lower += off * sizeof(indx_t);

	assert(ldp->lower <= ldp->upper);
	assert(rdp->lower <= rdp->upper);

	*out_left = l_mp;
	*out_right = r_mp;

	printf("->> old: %d left: %d right: %d\n", mp->pgno, l_mp->pgno, r_mp->pgno);
	printf("old_npg: %d left_npg: %d right_npg: %d\n", mp->npg, l_mp->npg, r_mp->npg);
	printf("left: upper: %d lower: %d flags: %x\n", ldp->upper, ldp->lower, ldp->flags);
	printf("right: upper: %d lower: %d flags: %x\n", rdp->upper, rdp->lower, rdp->flags);
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
	
/*
	pdp->upper = pmp->npg * PAGE_SIZE;

	switch (ldp->flags & DP_TYPE) {
	case DP_BLEAF:
		dl = GETDLEAF(ldp, 0);
		assert(dl->ksize && dl->ksize <= DP_MAX_KSIZE);
		nbytes = NDINTERNAL(dl->ksize);
		pdp->linp[0] = pdp->upper -= nbytes;
		dest = (char *)pdp + pdp->upper;
		__wr_dinternal(dest, dl->bytes, dl->ksize, lmp->pgno);
		break;

	case DP_BINTERNAL:
		di = GETDINTERNAL(ldp, 0);
		assert(di->ksize && di->ksize <= DP_MAX_KSIZE);
		nbytes = NDINTERNAL(di->ksize);
		pdp->linp[0] = pdp->upper -= nbytes;
		dest = (char *)pdp + pdp->upper;
		__wr_dinternal(dest, di->bytes, di->ksize, lmp->pgno);
		break;

	default:
		assert(0);
	}
*/
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

	assert(pdp->lower <= pdp->upper);

	/* Unpin the root page, set to btree internal page. */
	pdp->flags = 0;
	pdp->flags |= DP_BINTERNAL;

//	pmp->flags |= MP_LEFTMOST | MP_RIGHTMOST;
	pmp->leftmost = true;
	printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>. new_level: lower:%d upper: %d\n", pdp->lower, pdp->upper);

	__check_order(pmp);
	__check_order(lmp);
	__check_order(rmp);
	validate(pmp);
	validate(lmp);
	validate(rmp);


	__check_links(pmp, lmp, rmp, 0);
}

static void
__bt_page(BTREE *t, struct mpage *mp, struct mpage *p_mp, indx_t indx,
	struct mpage *l_mp, struct mpage *r_mp)
{
	struct dpage *rdp, *ldp, *pdp;
	void *dest;
	uint32_t nbytes;
	DLEAF *dl;
	DINTERNAL *di;
	int err;
	indx_t nxtindx;
	int i;

	rdp = r_mp->dp;
	ldp = l_mp->dp;
	pdp = p_mp->dp;

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

	printf("parent: %d indx:%d old: %d left: %d right: %d\n", p_mp->pgno, indx, mp->pgno, l_mp->pgno, r_mp->pgno);
	printf("parent_npg:%d old_npg: %d left_npg: %d right_npg: %d\n", p_mp->npg, mp->npg, l_mp->npg, r_mp->npg);
	printf("left: upper: %d lower: %d flags: %x\n", ldp->upper, ldp->lower, ldp->flags);
	printf("right: upper: %d lower: %d flags: %x\n", rdp->upper, rdp->lower, rdp->flags);

////	for (i = 0; i < DP_NXTINDX(pdp); i++) {
//	DINTERNAL *di = GETDINTERNAL(pdp, i);
//		printf("%d ", di->pgno);
//	}
	printf ("\n");
	__check_order(p_mp);
	__check_order(l_mp);
	__check_order(r_mp);
	validate(p_mp);
	validate(l_mp);
	validate(r_mp);

	__check_links(p_mp, l_mp, r_mp, indx);
}

int __bt_split(BTREE *t, struct mpage *mp)
{
	struct mpage *lmp, *rmp, *pmp, *nr_mp;
	struct dpage *dp;
	indx_t indx;
	int err;

	bt_page_lock(mp, PAGE_LOCK_EXCL);

	assert(mp->npg > 1);
//	assert(!(mp->flags & MP_DELETED));
	if (mp->flags & MP_DELETED) {
		bt_page_unlock(mp);
		return 0;
	}

	dp = mp->dp;
	while(mp->npg > 1 && DP_NXTINDX(dp) &&
		(dp->upper - dp->lower) >= PAGE_SIZE * (mp->npg - 1)) { 

		err = __bt_page_shrink(t, mp);
		assert(!err);
		dp = mp->dp;
	}

	assert(!(mp->flags & MP_DELETED));
	if (mp->npg == 1 || !DP_NXTINDX(dp)) {
		mp->flags &= ~MP_INSPLQ;
		bt_page_unlock(mp);
		return 0;
	}

	mp->flags |= MP_SPLITTING;
	mp->flags &= ~MP_INSPLQ;
	bt_page_unlock(mp);

	__bt_psplit(t, mp, &lmp, &rmp);

	printf("Splitting :%ld\n", mp->pgno);
	
	nr_mp = NULL;
	do {
		pmp = __get_parent_locked_excl(t, mp, &indx);
		if (IS_ERR(pmp))
			return PTR_ERR(pmp);

		assert (pmp->npg < 15); 

		if (pmp->flags & MP_METADATA) {
			
			assert(pmp->pgno == 0);
			if (!nr_mp) {
				bt_page_unlock(pmp);
				bt_page_put(pmp);

				nr_mp = bt_page_new(1);
				if (IS_ERR(nr_mp)) 
					return PTR_ERR(nr_mp);
				continue;
			}
			__bt_root(t, mp, nr_mp, lmp, rmp);
			pmp->md->root_pgno = nr_mp->pgno;
			printf("SETTING NEW ROOT: %d\n", pmp->md->root_pgno);
		} else {

			if (nr_mp)
				nr_mp->flags |= MP_DELETED;

			__bt_page(t, mp, pmp, indx, lmp, rmp);
		}
		break;
	} while (1);
	
	if (lmp->npg > 1) {
		pthread_mutex_lock(&splq_mutex);
		if (!(lmp->flags & MP_INSPLQ)) {
			// printf("QQQQ splitting :%ld\n", mp->pgno);
			TAILQ_INSERT_TAIL(&splq_head, lmp, spl_entries);
			lmp->flags |= MP_INSPLQ;
			bt_page_ref(lmp);
			pthread_cond_signal(&splq_cond);
			assert(!(lmp->flags & MP_DELETED));
		}
		pthread_mutex_unlock(&splq_mutex);
	}
	if (rmp->npg > 1) {
		pthread_mutex_lock(&splq_mutex);
		if (!(rmp->flags & MP_INSPLQ)) {
			// printf("QQQQ splitting :%ld\n", mp->pgno);
			TAILQ_INSERT_TAIL(&splq_head, rmp, spl_entries);
			rmp->flags |= MP_INSPLQ;
			bt_page_ref(rmp);
			pthread_cond_signal(&splq_cond);
			assert(!(rmp->flags & MP_DELETED));
		}
		pthread_mutex_unlock(&splq_mutex);
	}
	bt_page_unlock(pmp);

	bt_page_lock(mp, PAGE_LOCK_EXCL);
	pthread_mutex_lock(&mp->mutex);	
	mp->flags &= ~MP_SPLITTING;
	mp->flags |= MP_DELETED;
	pthread_cond_broadcast(&mp->cond);
	pthread_mutex_unlock(&mp->mutex);		
	bt_page_unlock(mp);

	if (nr_mp) 
		bt_page_put(nr_mp);
	bt_page_put(lmp);
	bt_page_put(rmp);
	bt_page_put(pmp);
	return 0;
}

int __bt_delete(BTREE *t, struct mpage *mp)
{
	struct mpage *pmp;
	struct dpage *dp;
	indx_t indx;
	int i;

	bt_page_lock(mp, PAGE_LOCK_EXCL);
	
	dp = mp->dp;
	if (!DP_NXTINDX(dp)) {
		mp->flags |= MP_DELETING;
		mp->flags &= ~MP_INDELQ;
	} else {
		if (mp->npg > 1 && !(mp->flags & MP_INSPLQ)) {

			pthread_mutex_lock(&splq_mutex);
			if (!(mp->flags & MP_INSPLQ)) {
				// printf("QQQQ splitting :%ld\n", mp->pgno);
				TAILQ_INSERT_TAIL(&splq_head, mp, spl_entries);
				mp->flags |= MP_INSPLQ;
				bt_page_ref(mp);
				pthread_cond_signal(&splq_cond);
			}
			pthread_mutex_unlock(&splq_mutex);
		}
		mp->flags &= ~MP_INDELQ;
		bt_page_unlock(mp);
		return 0;
	}
	bt_page_unlock(mp);

	pmp = __get_parent_locked_excl(t, mp, &indx);
	if (IS_ERR(pmp))
		return PTR_ERR(pmp);

	if (pmp->flags & MP_METADATA) {
		bt_page_unlock(pmp);

		bt_page_lock(mp, PAGE_LOCK_EXCL);

		dp = mp->dp;

		dp->flags &= ~DP_BINTERNAL;
		dp->flags |= DP_BLEAF;
		dp->lower = DP_HDRLEN;
		dp->upper = mp->npg * PAGE_SIZE;

		mp->flags &= ~MP_DELETING;

		bt_page_unlock(mp);

		pthread_mutex_lock(&mp->mutex);	
		mp->flags &= ~MP_DELETING;
		pthread_cond_broadcast(&mp->cond);
		pthread_mutex_unlock(&mp->mutex);		

		bt_page_put(pmp);
		return 0;
	} else {
		__remove_internal_at(pmp, NULL, indx);
		for (i = 0; i < DP_NXTINDX(pmp->dp); i++) {
			DINTERNAL *di = GETDINTERNAL(pmp->dp, i);
			assert(di->pgno != mp->pgno);
		}
		__check_order(pmp);
		if (DP_NXTINDX(pmp->dp) == 0) {
			pthread_mutex_lock(&delq_mutex);
			if (!(pmp->flags & MP_INDELQ)) {
		// printf("QQQQ splitting :%ld\n", mp->pgno);
				TAILQ_INSERT_TAIL(&delq_head, pmp, del_entries);
				pmp->flags |= MP_INDELQ;
				bt_page_ref(pmp);
				pthread_cond_signal(&delq_cond);
				assert(!(pmp->flags & MP_DELETED));
			}
			pmp->flags |= MP_DELETING;
			pthread_mutex_unlock(&delq_mutex);
		}	
	}
	bt_page_unlock(pmp);

	bt_page_lock(mp, PAGE_LOCK_EXCL);
	pthread_mutex_lock(&mp->mutex);	
	mp->flags &= ~MP_DELETING;
	mp->flags |= MP_DELETED;
	pthread_cond_broadcast(&mp->cond);
	pthread_mutex_unlock(&mp->mutex);		
	bt_page_unlock(mp);
	bt_page_put(pmp);
	return 0;
}

int exito;

void *splitter(void *arg)
{
	int err;
	BTREE *t = (BTREE *) arg;
	struct mpage *mp;

	while (1) {
		pthread_mutex_lock(&splq_mutex);
		while ((mp = splq_head.tqh_first) == NULL && !exito)
			pthread_cond_wait(&splq_cond, &splq_mutex);

		if (mp)
		   	TAILQ_REMOVE(&splq_head, mp, spl_entries);
		pthread_mutex_unlock(&splq_mutex);

		if (!mp) break;
	//	pthread_mutex_lock(&_m);
		err = __bt_split(t, mp);
	//	pthread_mutex_unlock(&_m);
		assert(!err);
		bt_page_put(mp);
	}
}

void *deleter(void *arg)
{
	int err;
	BTREE *t = (BTREE *) arg;
	struct mpage *mp;

	while (1) {
//		sleep(1); continue;
		pthread_mutex_lock(&delq_mutex);
		while ((mp = delq_head.tqh_first) == NULL && !exito)
			pthread_cond_wait(&delq_cond, &delq_mutex);

		if (mp)
			TAILQ_REMOVE(&delq_head, mp, del_entries);
		pthread_mutex_unlock(&delq_mutex);

		if (!mp) break;
		err = __bt_delete(t, mp);
		assert(!err);
		bt_page_put(mp);
	}
}


#if 0
static jjj = 0;

pthread_mutex_t _mutex = PTHREAD_MUTEX_INITIALIZER;


void *inserter(void *arg)
{
	BTREE *t = (BTREE *) arg;
	char vb[250];
	char kb[250];


	unsigned long k;

	pthread_mutex_lock(&_mutex);
	k = ++jjj;
	pthread_mutex_unlock(&_mutex);

	printf("CHOOSING K:%d\n", k);


	while (1) {
		DBT key, val;
		unsigned int rr = random();
		
		*(unsigned long *) kb = rr / 16 + k;
		*(unsigned long *) vb = rr / 16 + k;

		key.data = kb;
		key.size = 50;

		val.data = vb;
		val.size = 250;

		err = __bt_put(t, &key, &val);
		assert(!err);
	}
}

void *test1(void *arg)
{
	BTREE *t = (BTREE *) arg;
	int err;
	unsigned long i, j;
	char vv[250];
	char kkk[200];

	unsigned long k;
	pthread_mutex_lock(&_mutex);
	k = ++jjj;
	pthread_mutex_unlock(&_mutex);

	printf("CHOOSING K:%d\n", k);

	for (i = 0; i < 10000; i++) {

		unsigned long kk = k * 1000000000 + i;
		DBT key, val;

		*(unsigned long *) kkk = kk;
		key.data = kkk;
		key.size = 50;//200;

		val.data =(void *) vv;
		val.size = 250;

	//	pthread_mutex_lock(&_m);
		err = __bt_put(t, &key, &val);
		assert(!err);


	for (j = 0; j <= 0; j++) {

		unsigned long k1k = k * 1000000000 + j;
		DBT key, val;

		*(unsigned long *) kkk = k1k;
		key.data = kkk;
		key.size = 50;//200;

		val.data = (void *)vv;
		val.size = 250;

		err = __bt_get(t, &key, &val);
		assert(!err);

		//printf("%d\n", j);
	}



	if (i == 10000-1) printf("sleeeeeping\n");
		//pthread_mutex_unlock(&_m);

	}

	sleep(0);
	printf ("starting looooookup\n");
	for (i = 0; i < 10000; i++) {

		unsigned long kk = k * 1000000000 + i;
		DBT key, val;

		*(unsigned long *) kkk = kk;
		key.data = kkk;
		key.size = 50;

		val.data = (void *)vv;
		val.size = 250;

		err = __bt_get(t, &key, &val);
		assert(!err);

		//printf("%d\n", j);
	}

	for (i = 0; i < 10000; i++) {

		unsigned long kk = k * 1000000000 + i;
		DBT key, val;

		*(unsigned long *) kkk = kk;
		key.data = kkk;
		key.size = 50;

		val.data = (void *)vv;
		val.size = 250;

		err = __bt_del(t, &key);
		assert(!err);

		//printf("%d\n", j);
	}



//	sleep(5);
	{
		unsigned long k1k = k * 1000000000 + j;
		DBT key, val;

		*(unsigned long *) kkk = k1k;
		key.data = kkk;
		key.size = 50;//200;

		val.data = (void *)vv;
		val.size = 250;

//		err = __bt_get(t, &key, &val);
//		assert(!err);
	}

	printf("done\n");
}
#endif
	
BTREE tt, *t = &tt;

#define MAX_ELE     (1000000)
#define MAX_THREAD  (64)

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

	//		*(uint32_t *)key_real = key;
			
			err = __bt_get(t, &kk, &vv);

			//err = oca_btree_lookup(obth, (void*)key_real, NULL);
			//
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

//			*(uint32_t *)key_real = key;

			*(uint32_t *) kb = key;
			kk.data = kb;
			kk.size = 32;


			*(uint32_t *) vb = key;
			vv.data = vb;
			vv.size = 250;

//			err = oca_btree_update(obth, (void*)key_real, (void *)key_real);
			err = __bt_put(t, &kk, &vv);
			if (!err) {	

				if (!pt) assert(!(bitmap[key/8]&(1<<(key%8))));
//				assert(!__bt_get(t, &kk, &vv));
				//bitmap[key/8]|=(1<<(key%8));
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


//			*(uint32_t*)key_real = key;
//			err = oca_btree_remove(obth, (void*)key_real, NULL);
			err = __bt_del(t, &kk);
			if (!err) {
				if (!pt) assert(bitmap[key/8]&(1<<(key%8)));
//				bitmap[key/8]&=~(1U<<(key%8));

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

	/*
	for (k=0;k<MAX_ELE;k++) {

		char k1[32] = {};

		*(uint32_t*)k1 = k;
		
		err = oca_btree_lookup(obth, (void*)k1, NULL);
		if (!OCA_IS_ERROR(err)) {
			bitmap[k/8]|=(1<<(k%8));
		} else if (err != ERRNO_ENOENT) {
			assert(0);
			printf("error in initial lookup.\n");
		} 
	}
	*/

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
	return 0;
}

int main()
{
	struct mpage *mp, *mp_md;
	struct dpage *dp;
	pthread_t testers[16];
	pthread_t splitters[16];
	pthread_t deleters[16];
	int i;

	tt.bt_cmp = __bt_defcmp;
	bt_page_init();
	
	mp_md = bt_page_new(1);
	if (IS_ERR(mp_md)) {
		return PTR_ERR(mp_md);
	}
	mp_md->flags = 0;
	mp_md->flags |= MP_METADATA;

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

	TAILQ_INIT(&splq_head);
	TAILQ_INIT(&delq_head);

	pthread_mutex_init(&splq_mutex, NULL);
	pthread_cond_init(&splq_cond, NULL);

	pthread_mutex_init(&delq_mutex, NULL);
	pthread_cond_init(&delq_cond, NULL);



	for (i = 0; i < 16; i++) 
		pthread_create(&splitters[i], NULL, splitter, t);

	for (i = 0; i < 16; i++) 
		pthread_create(&deleters[i], NULL, deleter, t);

	/*
	for (i = 0; i < 16; i++) {
		pthread_create(&testers[i], NULL, test, (void *) &t);
	}



	for (i = 0; i < 16; i++) 
		pthread_join(testers[i], NULL);
*/
	test();

	exito = 1;
	pthread_cond_broadcast(&splq_cond);
	pthread_cond_broadcast(&delq_cond);

	//sleep(100);
	
	for (i = 0; i < 16; i++) 
		pthread_join(splitters[i], NULL);
	for (i = 0; i < 16; i++) 
		pthread_join(deleters[i], NULL);
}
