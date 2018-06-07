#include "global.h"
#include "lm_int.h"

static uint64_t lgblk_seqno;
static struct list_head lbs_list;
static struct list_head log_list;
static struct list_head full_log_list;
static pthread_cond_t	lg_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t	lb_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t	lg_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t	lb_lock = PTHREAD_MUTEX_INITIALIZER;

static void __put_sect_coff(lm_log_t *lg, struct sect_dlm *dlm, loff_t coff)
{
	assert((coff & LOG_ALIGN_MASK) == 0);
	if (lg->mrkr == LOG_MRKR_INIT) {
		dlm->coff[0] = coff >> LOG_ALIGN_SHFT;
		dlm->coff[1] = 0;
	} else {
		dlm->coff[1] = coff >> LOG_ALIGN_SHFT;
		dlm->coff[0] = 0;
	}
}

static loff_t __get_sect_coff(lm_log_t *lg, struct sect_dlm *dlm)
{
	if (lg->mrkr == LOG_MRKR_INIT)
		return dlm->coff[0] << LOG_ALIGN_SHFT;
	else 
		return dlm->coff[1] << LOG_ALIGN_SHFT;
}

static struct sect_dlm *__lb_next_ps_dlm(lg_blk_t *lb)
{
	return &lb->ps_dlm[1 & lb->psi++];
}

/* Initialize full sector header and tailer. */
static void __lb_init_fs_mrkrs(lg_blk_t *lb)
{
	lb->fs_dlm.mrkr = lb->lg->mrkr;
	__put_sect_coff(lb->lg, &lb->fs_dlm, SECT_TLR_OFFSET); 
}

static void __mark_reserved(lg_blk_t *lb)
{
	if (lb->nreserved++ == 0 && !(lb->flags & LB_FLAG_DIRTY)) {
		lb->seqno = lgblk_seqno++;
		lb->flags |= LB_FLAG_DIRTY;
	}
}

static int
__lg_write(lm_log_t *lg, struct iovec *iov, int cnt, loff_t off, size_t size)
{
	ssize_t b, ret;

	printf("Flushing @ %d %d\n", (int)off, (int)size);
	if (lg->mmaped_addr) {
		size_t len = 0, i;

		for (i = 0; i < cnt; i++) {
			memcpy(lg->mmaped_addr + off + len, iov[i].iov_base,
			    iov[i].iov_len);
			len += iov[i].iov_len;
		}
		return 0;
	} 
	if (size != (b = pwritev(lg->fd, iov, cnt, lg->base_offset + off))) 
		return -EIO;
	return 0;
}

static size_t
__lg_read(lm_log_t *lg, void *data, size_t size, loff_t off)
{
	size_t b;
	size_t len = MIN(size, lg->size - off);

	if (lg->mmaped_addr) {
		memcpy(data, lg->mmaped_addr + off, len);
		return len;
	} 
	if (len != (b = pread(lg->fd, data, len, lg->base_offset + off)))
		return -EIO;
	return len;
}

static void __lb_free(lg_blk_t *lb)
{
	if (lb->sect)
		free(lb->sect);
	if (lb->iov)
		free(lb->iov);
	free(lb);
}

static lg_blk_t *__lb_alloc(void)
{
	lg_blk_t *lb;

	if (!(lb = malloc(sizeof (lg_blk_t))))
		return NULL;
	if (!(lb->sect = malloc(SECT_SIZE))) {
		free(lb);
		return NULL;
	}
	if (!(lb->iov = malloc(sizeof (struct iovec) * LOG_MAX_IOV))) {
		free(lb->sect);
		free(lb);
		return NULL;
	}
	lb->iovidx = 0;
	lb->iovmax = LOG_MAX_IOV;
	lb->off = lb->coff = 0;
	lb->psi = 0;
	lb->lsh_iovidx = 0;	
	lb->fst_iovidx = 0;		
	lb->nreserved = 0;
	lb->flags = 0;
	lb->io_no = 0;
	lb->err = 0;
	lb->state = LB_STATE_NOIO;
	return lb;
}

static int __lg_reset(lm_log_t *lg)
{
	struct sect_dlm hdr;
	struct sect_dlm tlr;
	struct iovec iov[3];
	int ret;
	
	hdr.mrkr = LOG_MRKR_FSWITCH(lg->mrkr);
	__put_sect_coff(lg, &hdr, 0); 
	tlr.mrkr = lg->mrkr;
	__put_sect_coff(lg, &tlr, 0); 

	iov[0].iov_base = &hdr;
	iov[0].iov_len = SECT_DLM_SIZE;
	iov[1].iov_base = lg->zero_sect;
	iov[1].iov_len = SECT_DATA_SIZE;
	iov[2].iov_base = &tlr;
	iov[2].iov_len = SECT_DLM_SIZE;
	if ((ret = __lg_write(lg, iov, 3, 0, SECT_SIZE)))
		return ret;
	if ((ret = fsync(lg->fd)))
		return ret;
	lg->mrkr = hdr.mrkr;
	return 0;
}

static void __lg_mark_available(lm_log_t *lg)
{
	list_del(&lg->list);
	lg->size_avail = (lg->size >> SECT_SHFT) * SECT_DATA_SIZE;
	lg->part_size = 0;
	lg->commit_count = 0;
	list_add_tail(&lg->list, &log_list);
	pthread_cond_broadcast(&lg_cond);
}

static int __process_full_logs(void)
{
	lm_log_t *lg;
	int ret = 0, n = 0; 

	while (!list_empty(&full_log_list)) {
		lg = list_first_entry(&full_log_list, lm_log_t, list);
		if (lg->commit_count)
			return n;
		lg->commit_count = 1;
		pthread_mutex_unlock(&lg_lock);
		ret = __lg_reset(lg);
		pthread_mutex_lock(&lg_lock);
		if (ret) {
			lg->commit_count = 0;
			break;
		}
		n++;
		__lg_mark_available(lg);
	}
	return n ? n : ret;
}

static void __lg_put(lm_log_t *lg)
{
	assert(lg->commit_count > 0);
	if (--lg->commit_count == 0) 
		__process_full_logs();
}

static void __lg_mark_full(lm_log_t *lg)
{
	pthread_mutex_lock(&lg_lock);
	list_add_tail(&lg->list, &full_log_list);
	__lg_put(lg);
	pthread_mutex_unlock(&lg_lock);
}

void lm_log_put(lm_log_t *lg)
{
	pthread_mutex_lock(&lg_lock);
	__lg_put(lg);
	pthread_mutex_unlock(&lg_lock);
}

static void __lb_remove(lg_blk_t *lb, bool isfull)
{
	list_del(&lb->lbs);
	pthread_cond_broadcast(&lb_cond);
	pthread_mutex_unlock(&lb_lock);
	if (isfull) 
		__lg_mark_full(lb->lg);
	__lb_free(lb);
	return; 
}

static void __lb_commit_finish(lg_blk_t *lb)
{
	if (lb->flags & (LB_FLAG_FULL|LB_FLAG_FORKED)) { 
		__lb_remove(lb, lb->flags & LB_FLAG_FULL);
		return;
	} 
	pthread_mutex_unlock(&lb_lock);
	lb->coff = lb->off;
	if (lb->off & SECT_MASK) {
		void *sect = lb->sect;
		int i;

		memmove(lb->iov, &lb->iov[lb->lsh_iovidx],
		    sizeof (struct iovec) * (lb->iovidx - lb->lsh_iovidx));
		lb->iovidx = lb->iovidx - lb->lsh_iovidx;
		lb->lsh_iovidx = 0;

		for (i = 1; i < lb->iovidx; i++) {
			memmove(sect, lb->iov[i].iov_base, lb->iov[i].iov_len);
			lb->iov[i].iov_base = sect;
			sect += lb->iov[i].iov_len;
		}
		assert(sect < lb->sect + SECT_SIZE);
	} else {
		lb->iovidx = 0;
		lb->lsh_iovidx = 0;
	}
	pthread_mutex_lock(&lb_lock);
	if (lb->flags & LB_FLAG_FORKED) {
		__lb_remove(lb, false);
		return; 
	}
	lb->cid = 0;
	lb->state  =  LB_STATE_NOIO;
	lb->flags &= ~LB_FLAG_DIRTY;
	lb->seqno = lgblk_seqno;
	pthread_cond_broadcast(&lb_cond);
	pthread_mutex_unlock(&lb_lock);
	return;
}

/* coff != off */
static int __lb_commit(lg_blk_t *lb)
{
	lm_log_t *lg = lb->lg;
	struct sect_dlm *dlm;
	size_t iovidx = lb->iovidx;
	struct iovec *iov = lb->iov; 
	loff_t sect_coff, sect_off;

	assert(lb->coff != lb->off);
	sect_coff = lb->coff & SECT_MASK;
	sect_off = lb->off & SECT_MASK;
	if (sect_coff) {
		dlm = iov[0].iov_base;
		dlm->mrkr = LOG_MRKR_PSWITCH(dlm->mrkr);
	} else {
		dlm = __lb_next_ps_dlm(lb);
		dlm->mrkr = lg->mrkr;
		dlm->flgs = SECT_FLAG_HDR;
		iov[0].iov_base = dlm;
	}
	if ((lb->coff >> SECT_SHFT) == (lb->off >> SECT_SHFT)) { 
		goto last;
	} else {
		__put_sect_coff(lg, dlm, SECT_TLR_OFFSET);
		iov[lb->fst_iovidx].iov_base = dlm;
	}
    	if (sect_off) {
		dlm = __lb_next_ps_dlm(lb);
		dlm->mrkr = lg->mrkr;
		dlm->flgs = 0;
		iov[lb->lsh_iovidx].iov_base = dlm;
last:
		__put_sect_coff(lg, dlm, sect_off);

	    	iov[iovidx].iov_base = lg->zero_sect;
	       	iov[iovidx++].iov_len = SECT_TLR_OFFSET - sect_off;
	
		iov[iovidx].iov_base = dlm;
		iov[iovidx++].iov_len = SECT_DLM_SIZE;
	}
	assert(iovidx <= lb->iovmax);
	return iovidx;
}

/* Enters with lock held, returns with lock held. */
static int lb_commit(lg_blk_t *lb)
{
	lm_log_t *lg = lb->lg;
	struct sect_dlm dlm;
	struct iovec *iov;
	size_t iovidx;
	loff_t coff, off;
	int ret = 0;

	if (lb->coff < lb->off) {
		iovidx = __lb_commit(lb);
		coff = lb->coff & ~SECT_MASK;
		off = (lb->off + SECT_MASK) & ~SECT_MASK; 
		iov = lb->iov;
	} else if (lb->flags & LB_FLAG_FULL) {
		assert(lb->coff == lb->off);
		coff = off = (lb->off + SECT_MASK) & ~SECT_MASK;
		iov = &lb->iov[lb->iovidx];
		iovidx = 0;
	} 
	if (lb->flags & LB_FLAG_FULL) {
		if (off < lg->size) {
			dlm.mrkr = lg->mrkr;
			dlm.flgs = SECT_FLAG_HDR;
			__put_sect_coff(lg, &dlm, SECT_DLM_SIZE);
			do {
				iov[iovidx].iov_base = &dlm;
				iov[iovidx++].iov_len = SECT_DLM_SIZE;
				iov[iovidx].iov_base = lg->zero_sect;
				iov[iovidx++].iov_len = SECT_DATA_SIZE;
				iov[iovidx].iov_base = &dlm;
				iov[iovidx++].iov_len = SECT_DLM_SIZE;
				off += SECT_SIZE;
			} while (off < lg->size);
		}
	} 
	if (iovidx) {
		if (!(ret = __lg_write(lg, iov, iovidx, coff, off - coff))) {
			pthread_mutex_lock(&lb_lock);
			lb->state = LB_STATE_DOSYNC;
			pthread_cond_broadcast(&lb_cond);
			pthread_mutex_unlock(&lb_lock);
		} else {
			pthread_mutex_lock(&lb_lock);
			lb->cid = 0;
			lb->state = LB_STATE_NOIO;
			lb->err = ret;
			pthread_cond_broadcast(&lb_cond);
			pthread_mutex_unlock(&lb_lock);
		}
	} else {
		pthread_mutex_lock(&lb_lock);
		__lb_commit_finish(lb);
	}
	return ret;
}

static void __unmark_reserved(lg_blk_t *lb)
{
	pthread_mutex_lock(&lb_lock);
	if (!--lb->nreserved && lb->state == LB_STATE_DOIO) {
		lb->state = LB_STATE_INIO;
		lb->io_no++;
		pthread_mutex_unlock(&lb_lock);
		lb_commit(lb);
	} else {
		pthread_mutex_unlock(&lb_lock);
	}
}

static int __lb_reserve(lg_blk_t *lb, size_t size)
{
	lm_log_t *lg = lb->lg;
	size_t len, sec;
	int prev_sect = 0;

	if (lg->size_avail < size) {
		lb->flags |= LB_FLAG_FULL;
		return -ENOSPC;
	}
	lg->size_avail -= size;
	len = lg->part_size + size;
	sec = len / SECT_DATA_SIZE;		
	if (lg->part_size) {
		if ((lg->part_size = len % SECT_DATA_SIZE)) {
			if (sec) {
				lb->iovidx += sec * 3 + 1;
				lb->lsh_iovidx = lb->iovidx - 2;
			} else {
				lb->iovidx += 1;
			}
		} else {
			assert(sec >= 1);
			lb->iovidx += sec * 3 - 1;
			if (sec > 1) {
				lb->lsh_iovidx = lb->iovidx - 3;
			}
		}
	} else {
		if ((lg->part_size = len % SECT_DATA_SIZE)) {
			if (sec) {
	    			lb->iovidx += sec * 3 + 2;
				lb->lsh_iovidx = lb->iovidx - 2;
			} else {
				lb->lsh_iovidx = lb->iovidx;
				lb->iovidx += 2;
			}
		} else {
			lb->iovidx += sec * 3;
			lb->lsh_iovidx = lb->iovidx - 3;
		}
	}
	lb->off = (lb->off & ~SECT_MASK) + (sec << SECT_SHFT); 
	if (lg->part_size) 
		lb->off += lg->part_size + SECT_DLM_SIZE;
	assert(lb->iovidx <= lb->iovmax);
	return 0;
}

static int lb_reserve(lg_idx_t *li, size_t size)
{
	lg_blk_t *lb = li->lb;
	int ret;

	li->off = lb->off; 
	li->iovidx = lb->iovidx; 
	if ((ret = __lb_reserve(lb, size)))
		return ret;
	__mark_reserved(lb);
	return 0;
}

static int
lb_reservev(lg_idx_t *li, struct iovec *iov, size_t iovcnt, size_t size)
{
	lg_blk_t *lb = li->lb;
	int ret;
	int i;

	li->off = lb->off; 
	li->iovidx = lb->iovidx; 
	for (i = 0; i < iovcnt; i++) {
		if ((ret = __lb_reserve(lb, iov[i].iov_len))) {
			lb->off = li->off;
			lb->iovidx = li->iovidx;
			return ret;
		}
	}
	__mark_reserved(lb);
	return 0;
}

static void __lb_write(lg_idx_t *li, void *data, size_t size)
{
	lg_blk_t *lb = li->lb;
	lm_log_t *lg = lb->lg;
	size_t len;

	do {
		if ((li->off & SECT_MASK) == 0) {
			lb->iov[li->iovidx].iov_base = &lb->fs_dlm;
			lb->iov[li->iovidx++].iov_len = SECT_DLM_SIZE;
			li->off += SECT_DLM_SIZE;
		}
		len = SECT_TLR_OFFSET - (li->off & SECT_MASK);
		lb->iov[li->iovidx].iov_base = data;
		if (size >= len) { 
			lb->iov[li->iovidx++].iov_len = len;
			if ((lb->coff >> SECT_SHFT) == (li->off >> SECT_SHFT))
				lb->fst_iovidx = li->iovidx;
			lb->iov[li->iovidx].iov_base = &lb->fs_dlm;
			lb->iov[li->iovidx++].iov_len = SECT_DLM_SIZE;
			li->off += len + SECT_DLM_SIZE;
			data += len;
		} else {
			lb->iov[li->iovidx++].iov_len = size;
			li->off += size;
			len = size;
		}
	} while (size -= len);
}

lm_log_t *lm_write(lg_idx_t *li, void *data, size_t size)
{
	lm_log_t *lg = li->lb->lg;
	__lb_write(li, data, size);
	__unmark_reserved(li->lb);
	return lg;
}

lm_log_t *
lm_writev(lg_idx_t *li, struct iovec *iov, size_t iovcnt, size_t size)
{
	lm_log_t *lg = li->lb->lg;
	int i;
	for (i = 0; i < iovcnt; i++)
		__lb_write(li, iov[i].iov_base, iov[i].iov_len);
	__unmark_reserved(li->lb);
	return lg;
}

static void __lg_free(lm_log_t *lg)
{
	pthread_mutex_lock(&lg_lock);
	list_add(&lg->list, &log_list);
	pthread_mutex_unlock(&lg_lock);
}

static lm_log_t *__lg_get(bool nowait)
{
	lm_log_t *lg;
	int ret = -EAGAIN;

	pthread_mutex_lock(&lg_lock);
	while (list_empty(&log_list)) {
		if (nowait || (ret = __process_full_logs()) < 0) {
			pthread_mutex_unlock(&lg_lock);
			return ERR_PTR(ret);
		}
		if (!ret)
			pthread_cond_wait(&lg_cond, &lg_lock);
	}
	lg = list_first_entry(&log_list, lm_log_t, list);
	list_del(&lg->list);
	pthread_mutex_unlock(&lg_lock);
	lg->commit_count = 1;
	return lg;
}

static lg_blk_t *__lb_get(void)
{
	lg_blk_t *lb = NULL, *new_lb = NULL;
	lm_log_t *lg, *new_lg = NULL;

	do {
		if (!list_empty(&lbs_list)) {
			lb = list_last_entry(&lbs_list, lg_blk_t, lbs);
			if (lb->flags & (LB_FLAG_FULL|LB_FLAG_FORKED)) {
				lb = NULL;
			} else if (lb->state == LB_STATE_NOIO) { 
				if (new_lb) 
					__lb_free(new_lb);
				if (new_lg) 
					__lg_free(new_lg);
				return lb;
			}
		}
		if (!new_lb) {
			pthread_mutex_unlock(&lb_lock);
			if (!(new_lb = __lb_alloc())) 
				return ERR_PTR(-ENOMEM);
			pthread_mutex_lock(&lb_lock);
		} else if (!lb && !new_lg) {
	    		if (!IS_ERR(new_lg = __lg_get(true))) 
				break;
			pthread_mutex_unlock(&lb_lock);
			if (IS_ERR(new_lg = __lg_get(false))) {
				if (new_lb)
					__lb_free(new_lb);
				return ERR_PTR(PTR_ERR(new_lg));
			}
			pthread_mutex_lock(&lb_lock);
		} else {
			break;
		}
	} while (true);

	if (lb) {
		if (new_lg) 
			__lg_free(new_lg);
		lg = lb->lg;
		lb->flags |= LB_FLAG_FORKED;
    		new_lb->coff = new_lb->off = (lb->off + SECT_MASK) & ~SECT_MASK;
		if (lg->part_size) {
			lg->size_avail -= SECT_DATA_SIZE - lg->part_size;
			lg->part_size = 0;
		}
		new_lb->lg = lg;
	} else {
		new_lb->lg = new_lg;
		new_lb->coff = new_lb->off = 0;
	}
	new_lb->seqno = lgblk_seqno;
	__lb_init_fs_mrkrs(new_lb);
	list_add_tail(&new_lb->lbs, &lbs_list);
	return new_lb;
}

int
lm_reservev(lg_idx_t *li, struct iovec *iov, size_t iovcnt, size_t size)
{
	int ret;

	pthread_mutex_lock(&lb_lock);
	do {
		if (IS_ERR(li->lb = __lb_get())) 
			return PTR_ERR(li->lb);
		if (!(ret = lb_reservev(li, iov, iovcnt, size))) {
			pthread_mutex_lock(&lg_lock);
			li->lb->lg->commit_count++;	
			pthread_mutex_unlock(&lg_lock);
			pthread_mutex_unlock(&lb_lock);
			return 0;
		} else if (ret == -ENOSPC) {
			li->lb->flags |= LB_FLAG_FULL;
		} else {
			break;
		}
	}  while (true);
	pthread_mutex_unlock(&lb_lock);
	return ret;
} 
int lm_reserve(lg_idx_t *li, size_t size)
{
	int ret;

	pthread_mutex_lock(&lb_lock);
	do {
		if (IS_ERR(li->lb = __lb_get())) 
			return PTR_ERR(li->lb);
		if (!(ret = lb_reserve(li, size))) {
			pthread_mutex_lock(&lg_lock);
			li->lb->lg->commit_count++;	
			pthread_mutex_unlock(&lg_lock);
			pthread_mutex_unlock(&lb_lock);
			return 0;
		} else if (ret == -ENOSPC) {
			li->lb->flags |= LB_FLAG_FULL;
		} else {
			break;
		}
	}  while (true);
	pthread_mutex_unlock(&lb_lock);
	return ret;
}

int lm_commit(void)
{
	lg_blk_t *lb;
	uint64_t seqno = lgblk_seqno;
	uint64_t p_seqno, p_io_no;
	static uint64_t cid = 1;
	uint64_t mycid;
	int sync_fd;
	int ret;

	pthread_mutex_lock(&lb_lock);
	mycid = cid++;
redo_1:
	sync_fd = 0;
	list_for_each_entry(lb, &lbs_list, lbs) {
		if (lb->seqno >= seqno) 
			break;
		switch (lb->state) {
		case LB_STATE_NOIO:
			if (lb->nreserved) {
				lb->cid = mycid;
				lb->state = LB_STATE_DOIO;
				break;
			} 
			if (lb->flags & (LB_FLAG_DIRTY|LB_FLAG_FULL)) {
				lb->io_no++;
				lb->cid = mycid;
    				lb->state = LB_STATE_INIO;
				pthread_mutex_unlock(&lb_lock);
				ret = lb_commit(lb);
				pthread_mutex_lock(&lb_lock);
				if (ret)  
					goto redo_2;
				goto redo_1;
			}
			break;
		case LB_STATE_INIO:
		case LB_STATE_DOIO:
		case LB_STATE_DOSYNC:
			break;
		default:
			assert(0);
		}
	}
redo_2:
	sync_fd = 0;
	list_for_each_entry(lb, &lbs_list, lbs) {
		if (lb->seqno >= seqno) 
			break;
		switch (lb->state) {
		case LB_STATE_NOIO:
			break;
		case LB_STATE_INIO:
		case LB_STATE_DOIO:
			if (lb->cid == mycid) {
				pthread_cond_wait(&lb_cond, &lb_lock);
				goto redo_2;
			}
			break;
		case LB_STATE_DOSYNC:
			if (lb->cid == mycid) 
				sync_fd = lb->lg->fd;
			break;
		default:
			assert(0);
		}
	}
	pthread_mutex_unlock(&lb_lock);
	ret = sync_fd ? fsync(sync_fd) : 0;
redo_3:
	pthread_mutex_lock(&lb_lock);
	list_for_each_entry(lb, &lbs_list, lbs) {
		if (lb->seqno >= seqno) 
			break;
		switch (lb->state) {
		case LB_STATE_NOIO:
			break;
		case LB_STATE_INIO:
		case LB_STATE_DOIO:
			assert(lb->cid != mycid);
			break;
		case LB_STATE_DOSYNC:
			if (lb->cid == mycid) { 
				if (ret == 0) {
					__lb_commit_finish(lb);
					goto redo_3;
				} else {
					lb->err = ret;
					lb->cid = 0;
					lb->state = LB_STATE_NOIO;
					pthread_cond_broadcast(&lb_cond);
				}
			}
			break;
		default:
			assert(0);
		}
	}

	p_io_no = 0;
	p_seqno = ~0ULL;
redo_4:
	list_for_each_entry(lb, &lbs_list, lbs) {
		if (lb->seqno >= seqno) 
			break;
		switch (lb->state) {
		case LB_STATE_NOIO:
			if (lb->flags & (LB_FLAG_DIRTY|LB_FLAG_FULL)) {
				assert(lb->err);
				ret = lb->err;
				goto done;
			}
			break;
		case LB_STATE_DOIO:
			pthread_cond_wait(&lb_cond, &lb_lock);
			goto redo_4;
		case LB_STATE_INIO:
		case LB_STATE_DOSYNC:
			assert(lb->cid != mycid);
			if (p_seqno == lb->seqno && p_io_no < lb->io_no) {
				assert(lb->err);
				ret = lb->err;
				goto done;
			} else {
				p_seqno = lb->seqno;
				p_io_no = lb->io_no;
			}
			pthread_cond_wait(&lb_cond, &lb_lock);
			goto redo_4;
		default:
			assert(0);
		}
	}
done:
	pthread_mutex_unlock(&lb_lock);
	return ret;
}

static int
__log_init(lm_log_t *lg, loff_t start_sect)
{
	struct iovec iov[3];
	struct sect_dlm hdr;
	struct sect_dlm tlr;
	int ret = 0;
	int i;

	tlr.mrkr = hdr.mrkr = LOG_MRKR_FSWITCH(lg->mrkr);
	__put_sect_coff(lg, &tlr, 0);
	__put_sect_coff(lg, &hdr, 0);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = SECT_DLM_SIZE;
	iov[1].iov_base = lg->zero_sect;
	iov[1].iov_len = SECT_DATA_SIZE;
	iov[2].iov_base = &tlr;
	iov[2].iov_len = SECT_DLM_SIZE;
	for (i = start_sect; i < (lg->size >> SECT_SHFT); i++) {
		if ((ret = __lg_write(lg, iov, 3, i << SECT_SHFT, SECT_SIZE)))
			return ret;
	}
	return fsync(lg->fd);
}

static int 
__recover_mrkr(lm_log_t *lg, struct sect_dlm *hdr, struct sect_dlm *tlr)
{
	printf("in:%2x\n", hdr->mrkr);
	switch (hdr->mrkr) {
	case LOG_MRKR_INIT:
	case LOG_MRKR_PSWITCH(LOG_MRKR_INIT):
		lg->mrkr = LOG_MRKR_INIT;
		break;
	case LOG_MRKR_FSWITCH(LOG_MRKR_INIT):
	case LOG_MRKR_FSWITCH(LOG_MRKR_PSWITCH(LOG_MRKR_INIT)):
		lg->mrkr = LOG_MRKR_FSWITCH(LOG_MRKR_INIT);
		break;
	default: 
		switch (tlr->mrkr) {
		case LOG_MRKR_INIT:
		case LOG_MRKR_PSWITCH(LOG_MRKR_INIT):
			lg->mrkr = LOG_MRKR_INIT;
			break;
		case LOG_MRKR_FSWITCH(LOG_MRKR_INIT):
		case LOG_MRKR_FSWITCH(LOG_MRKR_PSWITCH(LOG_MRKR_INIT)):
			lg->mrkr = LOG_MRKR_FSWITCH(LOG_MRKR_INIT);
			break;
		default:
			return -ENXIO;
		}
	}
	printf("out:%2x\n", lg->mrkr);
	return 0;
}

static ssize_t
__recover_sector(lm_log_t *lg, void *buf, loff_t sect)
{
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	int ret;

	if (SECT_SIZE != __lg_read(lg, buf, SECT_SIZE, sect << SECT_SHFT))
		return -EIO;

	hdr = (struct sect_dlm *) (buf + SECT_HDR_OFFSET);
	tlr = (struct sect_dlm *) (buf + SECT_TLR_OFFSET); 

	if (sect == 0 && (ret = __recover_mrkr(lg, hdr, tlr))) 
		return ret;

	if (hdr->mrkr == tlr->mrkr)  
		return __get_sect_coff(lg, hdr);
	else 
	 	return __get_sect_coff(lg, tlr);
}

int
log_recover(lm_log_t *lg, void *buf, size_t size, int idx, lm_rcb_t cb,
    void *cb_arg)
{
	loff_t off = 0, sec_off;
	ssize_t len, sec;
	ssize_t ret_len;
	ssize_t total_len = 0;
	int err, i;
	void *sect;

	if ((sect = malloc(SECT_SIZE)))
		return -ENOMEM;

	for (i = 0; i < lg->size >> SECT_SHFT; i++) {
		if ((len = __recover_sector(lg, sect, i)) < 0) 
			return len;
		len -= SECT_DLM_SIZE;
		memmove(buf + off, sect + SECT_DLM_SIZE, len);
		off += len;
		if ((size - off) < SECT_DATA_SIZE) {
			if ((ret_len = (*cb)(buf, off, idx, cb_arg)) < 0) 
				return ret_len;
			memmove(buf, buf + ret_len, off - ret_len);
			off -= ret_len;
			total_len += ret_len;
		}
		if (len < SECT_DATA_SIZE)
			break;
	}
	ret_len = 0;
	if (off && ((ret_len = (*cb)(buf, off, idx, cb_arg)) < 0)) 
		return ret_len;
	total_len += ret_len;
	sec = total_len / SECT_DATA_SIZE;
	sec_off = total_len % SECT_DATA_SIZE;
//	lg->off = lg->coff = (sec << SECT_SHFT);
//	if ((err = log_commit(lg)))
//		return err;
	if (sec_off) {
		if (SECT_SIZE != __lg_read(lg, sect, SECT_SIZE, sec)) 
			return -EIO;
//		if ((err = log_write(lg,sect + SECT_DLM_SIZE, sec_off)))
//			return err;
//		if ((err = log_commit(lg)))
//			return err;
	}
	return __log_init(lg, sec + 1);
}

void log_free(lm_log_t *lg)
{
	if (lg->zero_sect) free(lg->zero_sect);
	free(lg);
}

lm_log_t *
log_alloc(int fd, loff_t offset, size_t size, void *addr)
{
	lm_log_t *lg;

	assert((size & SECT_MASK) == 0);
	if (!(lg = malloc(sizeof (lm_log_t))))
		return ERR_PTR(-ENOMEM);
	if (!(lg->zero_sect = calloc(1, SECT_SIZE))) {
		free(lg);
		return ERR_PTR(-ENOMEM);
	}
	if (addr) {
		lg->mmaped_addr = addr;
		lg->fd = -1;
	} else {
		lg->fd = fd;
		lg->base_offset = offset;
		lg->mmaped_addr = NULL;
	}
	lg->mrkr = LOG_MRKR_INIT;
	lg->commit_count = 0;
	lg->size = size;
	lg->size_avail = (size >> SECT_SHFT) * SECT_DATA_SIZE;
	lg->part_size = 0;
	return lg;
}

static size_t
__recover(void *data, size_t size, int idx, void *arg)
{
	printf("hai %ld\n", size);
	return size;
}
#if 0
int 
lm_set_valid_range(int in_head, int in_tail)
{
	head = in_head;
	tail = in_tail;
	eprintf("head:%d tail:%d\n", head, tail);
}

int
lm_scan(lm_rcb_t rcb, void *arg)
{
	int i, ret;
	void *buf;

	if (!(buf = malloc(8192)))
		return -ENOMEM;
	if (head < tail) {
		for (i = tail; i < TX_LOG_NBLKS; i++) {
			eprintf("recovering log %d\n", i);
			if ((ret = log_recover(logs[i], buf, 8192, i, rcb,
			    arg))) {
				if (ret == -ENXIO) {
					if ((ret = log_finish(logs[i]))) {
						free(buf);
						return ret;
					}
				} else if (ret != -EAGAIN) { 
					free(buf);
					return ret;
				}
			}
		}
		i = 0;
	} else {
		i = tail;
	}
	for (; i <= head; i++) {
		eprintf("recovering log %d\n", i);
		if ((ret = log_recover(logs[i], buf, 8192, i, rcb, arg))) {
			if (ret == -ENXIO) {
				if ((ret = log_finish(logs[i]))) {
					free(buf);
					return ret;
				}
			} else if (ret != -EAGAIN) { 
				free(buf);
				return ret;
			}
		}
	}
	free(buf);
	return 0;
}
#endif
void lm_system_exit()
{
	return;
}

int lm_system_init(int fd, loff_t off)
{
	lm_log_t *lg;
	int i, ret;

	if (LOG_ALIGN_SIZE > SECT_DLM_SIZE) {
		printf("LOG: Increase size of dlm->coff.\n");
		return -1;
	}
	INIT_LIST_HEAD(&lbs_list);
	INIT_LIST_HEAD(&log_list);
	INIT_LIST_HEAD(&full_log_list);

	for (i = 0; i < TX_LOG_NBLKS; i++) {
		if (IS_ERR(lg = log_alloc(fd, 
		    off + (i << TX_LOG_BLK_SHFT), TX_LOG_BLK_SIZE,
		    NULL))) {
	    		return PTR_ERR(lg);
		}
		list_add(&lg->list, &log_list);
	}
	return 0;
}

long
lm_mkfs(int fd, loff_t off)
{
	lm_log_t *lg;
	int i, ret;

	pthread_mutex_init(&lg_lock, NULL);
	pthread_cond_init(&lg_cond, NULL);
	pthread_mutex_init(&lb_lock, NULL);
	pthread_cond_init(&lb_cond, NULL);

	for (i = 0; i < TX_LOG_NBLKS; i++) {
		if (IS_ERR(lg = log_alloc(fd, off + (i << TX_LOG_BLK_SHFT),
		    TX_LOG_BLK_SIZE, NULL))) {
	    		return PTR_ERR(lg);
		}

		if ((ret = __log_init(lg, 0)))
			return ret;
		log_free(lg);
	}
	return (TX_LOG_NBLKS << TX_LOG_BLK_SHFT) >> PAGE_SHFT;
}

#ifdef TEST
static size_t
__log_recover(void *data, size_t size, int idx, void *arg)
{
	printf("hai %ld\n", size);
	return size;
}

struct list_head list, flist;
static pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t _cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t fcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t ccond = PTHREAD_COND_INITIALIZER;
static uint64_t __seqno;
int nnn;

struct dop {
	uint32_t n;
	uint32_t base;
	uint64_t seqno;
	uint32_t num[0];
};

struct op {
	struct list_head list;
	lm_log_t *lg;
	struct dop dop[0];
};

void *txer(void *arg)
{
	struct op *op;
	int n;
	int i;

	while (1) { 
		pthread_mutex_lock(&_lock);
		while (nnn > 100000) 
			pthread_cond_wait(&ccond, &_lock);
		pthread_mutex_unlock(&_lock);
		
		n = 1 + random() % 100;

		op = malloc(sizeof (struct op) + sizeof(struct dop) +
		    sizeof(uint32_t) * n);
		assert(op);

		op->dop[0].n = n;
		op->dop[0].base = random();
		for (i = 0; i < n; i++) 
			op->dop[0].num[i] = op->dop[0].base + i;

		pthread_mutex_lock(&_lock);
		op->dop->seqno = __seqno++;
		list_add_tail(&op->list, &list);
		pthread_cond_broadcast(&_cond);
		nnn++;
		pthread_mutex_unlock(&_lock);
	}
	return NULL;
}

void *logger(void *arg)
{
	lg_idx_t li;
	size_t size;
	int ret;
	struct op *op;

	pthread_mutex_lock(&_lock);
	while (1) {
		while (list_empty(&list)) 
			pthread_cond_wait(&_cond, &_lock);
		op = list_first_entry(&list, struct op, list);
		list_del(&op->list);
		pthread_mutex_unlock(&_lock);

		size = sizeof (struct dop) + op->dop->n * sizeof(uint32_t);
		if (ret = lm_reserve(&li, size)) {
			eprintf("error %d\n", ret);
			break;
		}

		//eprintf("lm_write: %p %p %d\n", li.lb->lg, li.lb, (int)li.off);
    		op->lg = lm_write(&li, op->dop, size); 
    
		if ((random() % 8 == 0) && (ret = lm_commit())) {
			eprintf("commit error %d\n", ret);
			break;
		}

		pthread_mutex_lock(&_lock);
		if (random() % 2) 
			list_add_tail(&op->list, &flist);
		else
			list_add(&op->list, &flist);
		pthread_cond_broadcast(&fcond);

	}
	pthread_mutex_unlock(&_lock);
	return NULL;
}

void *releser(void *arg)
{
	struct op *op;
	pthread_mutex_lock(&_lock);
	while (1) {
		while (list_empty(&flist)) 
			pthread_cond_wait(&fcond, &_lock);
		op = list_first_entry(&flist, struct op, list);
		list_del(&op->list);
		if (--nnn == 100000)
			pthread_cond_broadcast(&ccond);
		pthread_mutex_unlock(&_lock);

		usleep(100);
		lm_log_put(op->lg);
		free(op);
		pthread_mutex_lock(&_lock);
	}
	pthread_mutex_unlock(&_lock);
	return NULL;
}

int main(int argc, char **argv)
{
	int fd;
	pthread_t t;
	int ret, i;

	INIT_LIST_HEAD(&list);
	INIT_LIST_HEAD(&flist);

	fd = open(argv[1], O_RDWR);
	assert(fd > 0);

	if (argv[2][0] == 'i') {
		exit(lm_mkfs(fd, 0));
	}
	ret = lm_system_init(fd, 0);
	assert(ret == 0);

	pthread_create(&t, NULL, txer, NULL);
	for (i = 0; i < 16; i++) 
		pthread_create(&t, NULL, logger, NULL);
	for (i = 0; i < 16; i++) 
		pthread_create(&t, NULL, releser, NULL);
	pthread_join(t, NULL);
}
#endif
