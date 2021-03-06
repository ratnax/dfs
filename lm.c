#include "global.h"
#include "lm_int.h"
 #include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

static uint64_t			 log_seqno;
static struct list_head		 lbs_list;
static struct list_head		 log_list;
static struct list_head		 full_log_list;
static pthread_cond_t		 lg_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t		 lb_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t		 lg_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t		 lb_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t		 flush_cond = PTHREAD_COND_INITIALIZER;
static struct io_context	*io_ctxt; 

static inline 
void __put_sect_coff(lm_log_t *lg, struct sect_dlm *dlm, loff_t coff)
{
	// assert((coff & LOG_ALIGN_MASK) == 0);
	if (lg->logid == 0) {
		dlm->coff[0] = coff >> LOG_ALIGN_SHFT;
		dlm->coff[1] = 0;
	} else {
		dlm->coff[1] = coff >> LOG_ALIGN_SHFT;
		dlm->coff[0] = 0;
	}
}

static inline loff_t __get_sect_coff(lm_log_t *lg, struct sect_dlm *dlm)
{
	if (lg->logid == 0)
		return dlm->coff[0] << LOG_ALIGN_SHFT;
	else 
		return dlm->coff[1] << LOG_ALIGN_SHFT;
}

static inline struct sect_dlm *__lb_next_ps_dlm(lg_blk_t *lb)
{
	return &lb->ps_dlm[1 & lb->psi++];
}

static inline void __lb_init_fs_mrkrs(lg_blk_t *lb)
{
	lb->fs_dlm.logid = lb->lg->logid;
	lb->fs_dlm.seqno = 0;
	lb->fs_dlm.flags = 0;
	__put_sect_coff(lb->lg, &lb->fs_dlm, SECT_TLR_OFFSET); 
}

static int
__lg_writev(lm_log_t *lg, struct iovec *iov, int cnt, size_t size, loff_t off)
{
	ssize_t b, ret;

	if (lg->mmaped_addr) {
		size_t len = 0, i;

		for (i = 0; i < cnt; i++) {
			memcpy(lg->mmaped_addr + off + len, iov[i].iov_base,
			    iov[i].iov_len);
			len += iov[i].iov_len;
		}
		return 0;
	} 
	if (size != (b = pwritev(lg->fd, iov, cnt, lg->base_offset + off))) {
		assert(0);
		return -EIO;
	}
	return 0;
}

static int
__lg_write(lm_log_t *lg, void *data, size_t size, loff_t off)
{
	ssize_t b, ret;

	if (lg->mmaped_addr) {
		size_t len = 0, i;

		memcpy(lg->mmaped_addr + off, data, size);
		return 0;
	} 
	if (size != (b = pwrite(lg->fd, data, size, lg->base_offset + off)))
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
	return 0;
}

static void __lb_free(lg_blk_t *lb)
{
	free(lb);
}

static lg_blk_t *__lb_alloc(void)
{
	lg_blk_t *lb;

	if ((lb = malloc(sizeof (lg_blk_t)))) {
		lb->iovidx = 0;
		lb->iovmax = LB_MAX_IOVCNT;
		lb->off = lb->coff = 0;
		lb->psi = 0;
		lb->lsh_iovidx = 0;	
		lb->fst_iovidx = 0;		
		lb->flags = 0;
		lb->last_err = 0;
		lb->state = LB_STATE_ACTIVE;
	}
	return lb;
}

static int __lg_reset(lm_log_t *lg)
{
	struct sect_dlm hdr;
	struct sect_dlm tlr;
	struct iovec iov[3];
	int ret;
	
	hdr.logid = !lg->logid; 
	hdr.seqno = 0;
	__put_sect_coff(lg, &hdr, 0); 
	tlr.logid = lg->logid;
	tlr.seqno = 0;
	__put_sect_coff(lg, &tlr, 0); 

	iov[0].iov_base = &hdr;
	iov[0].iov_len = SECT_DLM_SIZE;
	iov[1].iov_base = lg->zero_sect;
	iov[1].iov_len = SECT_DATA_SIZE;
	iov[2].iov_base = &tlr;
	iov[2].iov_len = SECT_DLM_SIZE;
	if ((ret = __lg_writev(lg, iov, 3, SECT_SIZE, 0)))
		return ret;
	if ((ret = fsync(lg->fd)))
		return ret;
	lg->logid = hdr.logid;
	return 0;
}

static void __lg_mark_available(lm_log_t *lg)
{
	list_del(&lg->list);
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

static void __lb_remove(lg_blk_t *lb)
{
	list_del(&lb->lbs);
	pthread_cond_broadcast(&lb_cond);
	pthread_mutex_unlock(&lb_lock);
	if (__is_full(lb)) 
		__lg_mark_full(lb->lg);
	__lb_free(lb);
	return; 
}

static void __lb_commit_finish(lg_blk_t *lb)
{
	size_t mod_off;

	if (__is_full(lb) || __is_forked(lb)) {
		__lb_remove(lb);
		return;
	} 
	mod_off = __sect_mod(lb->off);
	if (__is_aio(lb) && mod_off) {
		lb->coff = __sect_floor(lb->off);
		lb->flags = LB_FLAG_NOHDR;
		lb->iovidx = lb->iovidx - lb->lsh_iovidx;
		memmove(lb->iovecs, lb->iovecs + lb->lsh_iovidx,
		    (lb->iovidx * sizeof(struct iovec)));
	} else {
		void *sect = lb->lg->sect;
		int i;

		if (mod_off) {
			for (i = lb->lsh_iovidx; i < lb->iovidx; i++) {
				if (lb->iovecs[i].iov_base != sect) {
					memmove(sect, lb->iovecs[i].iov_base,
					    lb->iovecs[i].iov_len);
				}
				sect += lb->iovecs[i].iov_len;
			}
			assert(sect < lb->lg->sect + SECT_SIZE);

			lb->iovecs[0].iov_base = lb->lg->sect;
			lb->iovecs[0].iov_len = mod_off;
			lb->iovidx = 1;
			lb->flags = LB_FLAG_NOHDR;
		} else {
			lb->flags = 0;
			lb->iovidx = 0;
		}
		lb->coff = lb->off;
	}
	lb->lsh_iovidx = 0;
	lb->state  =  LB_STATE_ACTIVE;
	pthread_cond_broadcast(&lb_cond);
	pthread_mutex_unlock(&lb_lock);
	return;
}

static void __lb_write_complete(lg_blk_t *lb, size_t bwrote)
{
	assert(lb->io_size == bwrote);
	pthread_mutex_lock(&lb_lock);
	if (lb->io_size == bwrote) {
		lb->state = LB_STATE_DOSYNC;
	} else {
		lb->state = LB_STATE_DOIO;
		lb->last_err = -EIO;
	}
	pthread_cond_broadcast(&lb_cond);
	pthread_mutex_unlock(&lb_lock);
}

static int
__lb_submit_io(lg_blk_t *lb, struct iovec *iov, size_t iovcnt, loff_t off,
    size_t size, bool async)
{
	lm_log_t *lg = lb->lg;
	struct iocb *iocb = &lb->iocb;
	int ret;
	struct sect_dlm *d = iov[0].iov_base;

	lb->io_size = size;
	if (async) {
		io_prep_pwritev(iocb, lg->fd, iov, iovcnt,
		    off + lg->base_offset);
		lb->iocb.data = (void *) lb;
		if ((ret = io_submit(io_ctxt, 1, &iocb)) == 1) 
			return 0;
		assert(0);
		ret = -EIO;
	} else {
		if ((ret = __lg_writev(lg, iov, iovcnt, size, off))) {
			__lb_write_complete(lb, 0);
		} else {
			__lb_write_complete(lb, size);
		}
	} 
	return ret;
}

static inline void __schedule_io(lg_blk_t *lb)
{
	__mark_aio(lb);
	lb->state = LB_STATE_DOIO;
}

static inline void __start_io(lg_blk_t *lb)
{
	lb->state = LB_STATE_INIO;
}

static int __lb_commit(lg_blk_t *lb, bool async)
{
	lm_log_t *lg = lb->lg;
	struct sect_dlm *d;
	struct iovec *iov;
	size_t iovidx = 0;
	size_t mod_off, mod_coff;
	loff_t coff, off;
	int ret = 0;

	if (lb->coff == lb->off) {
		pthread_mutex_lock(&lb_lock);
		__lb_commit_finish(lb);
		return 0;
	}
	assert(lb->coff < lb->off);
	iov = lb->iovecs;
	coff = __sect_floor(lb->coff);
	mod_coff = __sect_mod(lb->coff);
	    
	if (mod_coff) {
		d = iov[0].iov_base;
		d->seqno++;
	} else {
		d = __lb_next_ps_dlm(lb);
		d->logid = lg->logid;
		d->seqno = 0;
		d->flags = __is_nohdr(lb) ? 0 : SECT_FLAG_HDR;
		iov[0].iov_base = d;
	}
	if (async) {
		off = __sect_floor(lb->off);
		assert(coff != off);
		if ((mod_off = __sect_mod(lb->off))) 
			iovidx = lb->lsh_iovidx;
		else
			iovidx = lb->iovidx;
    		__put_sect_coff(lg, d, SECT_TLR_OFFSET);
		iov[lb->fst_iovidx].iov_base = d;
	} else {
		off = __sect_ceiling(lb->off);
		mod_off = __sect_mod(lb->off);
		iovidx = lb->iovidx;
		if (coff == __sect_floor(off)) {
			goto last;
		} else {
			__put_sect_coff(lg, d, SECT_TLR_OFFSET);
			iov[lb->fst_iovidx].iov_base = d;
		}
        	if (mod_off) {
			d = __lb_next_ps_dlm(lb);
			d->logid = lg->logid;
			d->seqno = 0;
			d->flags = 0;
			iov[lb->lsh_iovidx].iov_base = d;
last:
			__put_sect_coff(lg, d, mod_off);
			iov[iovidx].iov_base = lg->zero_sect;
			iov[iovidx++].iov_len = SECT_TLR_OFFSET - mod_off;
			iov[iovidx].iov_base = d;
			iov[iovidx++].iov_len = SECT_DLM_SIZE;
		}
	}
	return __lb_submit_io(lb, iov, iovidx, coff, off - coff, async);
}

static size_t  __lb_write(lg_blk_t *lb, void *data, size_t size)
{
	size_t len;

	do {
		if ((lb->off & SECT_MASK) == 0) {
			lb->lsh_iovidx = lb->iovidx;
			lb->iovecs[lb->iovidx].iov_base = &lb->fs_dlm;
			lb->iovecs[lb->iovidx++].iov_len = SECT_DLM_SIZE;
			lb->off += SECT_DLM_SIZE;
			if (lb->off == SECT_DLM_SIZE) {
				lb->iovecs[lb->iovidx].iov_base = 
				    &lb->lg->seqno;
				lb->iovecs[lb->iovidx++].iov_len =
				    sizeof (uint64_t);
				lb->off += sizeof (uint64_t);
			}
		}
		len = SECT_TLR_OFFSET - (lb->off & SECT_MASK);
		lb->iovecs[lb->iovidx].iov_base = data;
		if (size >= len) { 
			lb->iovecs[lb->iovidx++].iov_len = len;
			if ((lb->coff >> SECT_SHFT) == (lb->off >> SECT_SHFT))
				lb->fst_iovidx = lb->iovidx;
			lb->iovecs[lb->iovidx].iov_base = &lb->fs_dlm;
			lb->iovecs[lb->iovidx++].iov_len = SECT_DLM_SIZE;
			lb->off += len + SECT_DLM_SIZE;
			data += len;
		} else {
			lb->iovecs[lb->iovidx++].iov_len = size;
			lb->off += size;
			len = size;
		}
		size -= len;
	} while (size && lb->off < lb->lg->size &&
	    (lb->iovidx + 3) < lb->iovmax);
	assert(lb->iovidx <= lb->iovmax);
	return size;
}

static void __lg_free(lm_log_t *lg)
{
	pthread_mutex_lock(&lg_lock);
	list_add(&lg->list, &log_list);
	pthread_mutex_unlock(&lg_lock);
}

static lm_log_t *__lg_get(void)
{
	lm_log_t *lg;

	pthread_mutex_lock(&lg_lock);
	if (list_empty(&log_list)) {
		pthread_mutex_unlock(&lg_lock);
		return NULL;
	}
	lg = list_first_entry(&log_list, lm_log_t, list);
	list_del(&lg->list);
	lg->seqno = log_seqno++;
	pthread_mutex_unlock(&lg_lock);
	lg->commit_count = 1;
	return lg;
}

static int __lg_wait(void)
{
	int ret;

	pthread_mutex_lock(&lg_lock);
	while (list_empty(&log_list)) {
		if ((ret = __process_full_logs()) < 0) {
			pthread_mutex_unlock(&lg_lock);
			return ret;
		}
		if (!ret && list_empty(&log_list))
			pthread_cond_wait(&lg_cond, &lg_lock);
	}
	pthread_mutex_unlock(&lg_lock);
	return 0;
}

static int __recover_active_lb(lm_log_t *lg, loff_t off)
{
	lg_blk_t *lb;

	if (!(lb = __lb_alloc())) 
		return -ENOMEM;
	lg->commit_count++;
	lb->lg = lg;
	lb->coff = lb->off = off;
	__lb_init_fs_mrkrs(lb);
	list_add_tail(&lb->lbs, &lbs_list);
	return 0;
}

static lg_blk_t *__lb_get(void)
{
	int ret;
	lg_blk_t *lb = NULL, *new_lb = NULL;
	lm_log_t *lg, *new_lg = NULL;

	if (!list_empty(&lbs_list)) {
		lb = list_last_entry(&lbs_list, lg_blk_t, lbs);
		if (__is_full(lb) || __is_forked(lb)) {
			lb = NULL;
		} else if (__is_active(lb)) {
			return lb;
		}
	}
	if (!new_lb && !(new_lb = __lb_alloc())) { 
		return ERR_PTR(-ENOMEM);
	} else if (!lb && !(new_lg = __lg_get())) {
		if (new_lb)
			__lb_free(new_lb);
		return ERR_PTR(-EBUSY);
	}
	if (lb) {
		size_t mod_off = __sect_mod(lb->off);

		assert(new_lg == NULL); 
		__mark_forked(lb);
		lg = lb->lg;
		if (__is_aio(lb) && mod_off) {
			/* Not a header even though coff is sect aligned */
			__mark_nohdr(new_lb);
			new_lb->coff = __sect_floor(lb->off);
			new_lb->off = lb->off;
			new_lb->iovidx = lb->iovidx - lb->lsh_iovidx;
			memmove(new_lb->iovecs, lb->iovecs + lb->lsh_iovidx,
				(new_lb->iovidx * sizeof(struct iovec)));
		} else {
			new_lb->coff = new_lb->off = lb->off;
			if (mod_off) {
				new_lb->iovecs[0].iov_base = lg->sect;
				new_lb->iovecs[0].iov_len = mod_off;
				new_lb->iovidx = 1;
			}
		}
		new_lb->lg = lg;
	} else {
		new_lb->lg = new_lg;
		new_lb->coff = new_lb->off = 0;
	}
	__lb_init_fs_mrkrs(new_lb);
	list_add_tail(&new_lb->lbs, &lbs_list);
	return new_lb;
}

void *io_cb(void *arg)
{
	struct io_event events[128];
	int n, i;

	while (1) {
		if ((n = io_getevents(io_ctxt, 1, 128, events, NULL)) <= 0) 
			continue;

		for (i = 0; i < n; i++) {
			__lb_write_complete(events[i].data, events[i].res);
		} 
	}
}

int lm_write(void *data, size_t size, lm_idx_t *li)
{
	lm_log_t *lg;
	lg_blk_t *lb, *lb2;
	loff_t off;
	size_t iovidx;
	int ret, len;

retry:
	pthread_mutex_lock(&lb_lock);
	if (IS_ERR(lb = __lb_get())) {
		pthread_mutex_unlock(&lb_lock);
		if (PTR_ERR(lb) == -EBUSY) {
			if ((ret = __lg_wait()))
				return ret;
			goto retry; 
		}
		return PTR_ERR(lb);
	}
	li->lg1 = lb->lg;
	li->soff = lb->off;
	iovidx = lb->iovidx;
	if ((len = __lb_write(lb, data, size))) {
		if (IS_ERR(lb2 = __lb_get())) {
			lb->off = li->soff;
			lb->iovidx = iovidx;
			pthread_mutex_unlock(&lb_lock);
			if (PTR_ERR(lb2) == -EBUSY) {
				if ((ret = __lg_wait()))
					return ret;
				goto retry; 
			}
			return PTR_ERR(lb2);
		}
		__schedule_io(lb);
		pthread_cond_signal(&flush_cond);
		__lb_write(lb2, data + size - len, len);
		li->lg2 = lb2->lg;
		pthread_mutex_lock(&lg_lock);
		li->lg2->commit_count++;	
		pthread_mutex_unlock(&lg_lock);
		lb = lb2;
	}
	pthread_mutex_lock(&lg_lock);
	li->lg1->commit_count++;	
	pthread_mutex_unlock(&lg_lock);
	li->eoff = lb->off;
	if (lb->off - lb->coff > SECT_SIZE) {
		__schedule_io(lb);
		pthread_cond_signal(&flush_cond);
	}
	pthread_mutex_unlock(&lb_lock);
	return 0;
}

int __lm_commit(uint64_t lg_seqno, loff_t off)
{
	lm_log_t *lg;
	lg_blk_t *lb;
	int sync_fd;
	int ret = 0;

	pthread_mutex_lock(&lb_lock);
redo_1:
	if (IS_ERR(lb = __lb_get())) {
		pthread_mutex_unlock(&lb_lock);
		return PTR_ERR(lb);
	}
	list_for_each_entry(lb, &lbs_list, lbs) {
		lg = lb->lg;
		if (lg->seqno > lg_seqno ||
		    lg->seqno == lg_seqno && lb->coff >= off)
			break;
		switch (lb->state) {
		case LB_STATE_ACTIVE:
			if (!__sect_mod(lb->off) || 
			    lg->seqno == lg_seqno && 
			    __sect_floor(lb->off) >= off) {
				__schedule_io(lb);
			}
			/* fallthrough */
		case LB_STATE_DOIO:
			__start_io(lb);
			pthread_mutex_unlock(&lb_lock);
			if ((ret = __lb_commit(lb, __is_aio(lb)))) {
				assert(0);
				return ret;
			}
			pthread_mutex_lock(&lb_lock);
			goto redo_1;
		case LB_STATE_INIO:
			if (!__is_aio(lb)) {
				pthread_cond_wait(&lb_cond, &lb_lock);
				goto redo_1;
			}
			break;
		case LB_STATE_DOSYNC:
			break;
		default:
			assert(0);
		}
	}
redo_2:
	sync_fd = 0;
	list_for_each_entry(lb, &lbs_list, lbs) {
		lg = lb->lg;
		if (lg->seqno > lg_seqno ||
		    lg->seqno == lg_seqno && lb->coff >= off)
			break;
		switch (lb->state) {
		case LB_STATE_ACTIVE:
		case LB_STATE_DOIO:
			assert(0);
			ret = lb->last_err;
			assert(ret);
			goto done;
		case LB_STATE_INIO:
			pthread_cond_wait(&lb_cond, &lb_lock);
			goto redo_2;
		case LB_STATE_DOSYNC:
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
		lg = lb->lg;
		if (lg->seqno > lg_seqno ||
		    lg->seqno == lg_seqno && lb->coff >= off)
			break;
		switch (lb->state) {
		case LB_STATE_ACTIVE:
		case LB_STATE_INIO:
		case LB_STATE_DOIO:
			assert(0);
			ret = lb->last_err;
			assert(ret);
			goto done;
		case LB_STATE_DOSYNC:
			if (ret == 0) {
				__lb_commit_finish(lb);
				goto redo_3;
			} else {
				lb->last_err = ret;
				lb->state = LB_STATE_DOSYNC;
				pthread_cond_broadcast(&lb_cond);
			}
			break;
		default:
			assert(0);
		}
	}
done:
	pthread_mutex_unlock(&lb_lock);
	return ret;
}

static void *flush_thread(void *arg)
{
	lg_blk_t *lb; 
	uint64_t seqno;
	loff_t off;

	while (1) {
		pthread_mutex_lock(&lb_lock);
		while (list_empty(&lbs_list))
			pthread_cond_wait(&flush_cond, &lb_lock);
		lb = list_last_entry(&lbs_list, lg_blk_t, lbs);
		seqno = lb->lg->seqno;
		if (__is_active(lb))
			off = lb->coff;
		else
			off = lb->off;
		pthread_mutex_unlock(&lb_lock);
		__lm_commit(seqno, off);
	}	
}

int lm_commit(lm_log_t *lg, loff_t off)
{
	return __lm_commit(lg->seqno, off);
}

static int __log_init(lm_log_t *lg, loff_t start_sect)
{
	int ret = 0, i;
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	static int j;

	hdr = (lg->sect + SECT_HDR_OFFSET);
	tlr = (lg->sect + SECT_TLR_OFFSET);
	hdr->flags = tlr->flags = 0;
	hdr->seqno = tlr->seqno = 0;
	__put_sect_coff(lg, hdr, SECT_HDR_OFFSET);	
	__put_sect_coff(lg, tlr, SECT_HDR_OFFSET);	
	tlr->logid = !lg->logid;
	for (i = start_sect; i < (lg->size >> SECT_SHFT); i++) {
		hdr->logid = (i == 0) ?  lg->logid : !lg->logid;
		if ((ret = __lg_write(lg, lg->sect, SECT_SIZE, i << SECT_SHFT)))
			return ret;
	}
	if ((ret = fsync(lg->fd))) 
		return ret;
	if (start_sect &&
	    (ret = __recover_active_lb(lg, start_sect << SECT_SHFT)))
		return ret;
	return 0;
}

static void 
__recover_mrkr(lm_log_t *lg, struct sect_dlm *hdr, struct sect_dlm *tlr)
{
	lg->logid = hdr->logid;
}

static ssize_t
__recover_sector(lm_log_t *lg, void *buf, loff_t sect, int *hdr_flag)
{
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	int ret, len;

	if ((ret = __lg_read(lg, buf, SECT_SIZE, sect << SECT_SHFT)))
		return ret;

	hdr = (struct sect_dlm *) (buf + SECT_HDR_OFFSET);
	tlr = (struct sect_dlm *) (buf + SECT_TLR_OFFSET); 

	if (sect == 0)
		__recover_mrkr(lg, hdr, tlr);

	if (hdr->seqno == tlr->seqno) {
		*hdr_flag = (hdr->flags & SECT_FLAG_HDR);
		len = __get_sect_coff(lg, hdr);
	} else {
		*hdr_flag = (tlr->flags & SECT_FLAG_HDR);
	 	len = __get_sect_coff(lg, tlr);
	}
	assert(len <= SECT_TLR_OFFSET);
	if (len >= SECT_DLM_SIZE)
		return len - SECT_DLM_SIZE;
	assert(len == 0);
	return 0;
}

static int
__lg_recover_seqno(lm_log_t *lg)
{
	int ret;
	int hdr_flag;

	if ((ret = __recover_sector(lg, lg->sect, 0, &hdr_flag)) < 0) 
		return ret;
	if (ret) {
		assert(ret > sizeof(uint64_t));
		lg->seqno = *(uint64_t *) (lg->sect + SECT_DLM_SIZE);
	} else {
		lg->seqno = ~0ULL;
	}
	return 0;
}

static int 
__call_rcb(lm_log_t *lg, void *buf, size_t size, lm_rcb_t cb, void *cb_arg)
{
	lb_rec_t *rec;
	int ret, len = 0;

	while ((ret = (*cb)(buf, size - len, cb_arg)) > 0) {
		lg->commit_count++;
		buf += ret;
		len += ret;
	}
	if (ret)
		return ret;
    	return len;
}

static int
__lg_recover(lm_log_t *lg, void *buf, size_t size, lm_rcb_t cb, void *cb_arg)
{
	loff_t off = 0, sec_off;
	ssize_t len, sec = 0;
	ssize_t ret = 0, skip = sizeof (uint64_t);
	ssize_t total_len = 0;
	int hdr_flag;
	int i;
	bool expect_hdr = true;

	for (i = 0; i < lg->size >> SECT_SHFT; i++) {
		if ((len = __recover_sector(lg, lg->sect, i, &hdr_flag)) < 0) 
			return len;
		if (!len)
			break;
		assert(len >= sizeof(uint64_t));
		if (expect_hdr) {
			if (!hdr_flag)
				break;
			assert(off == 0);
			sec = i;
			total_len = 0;
		}
		memmove(buf + off, lg->sect + SECT_DLM_SIZE, len);
		off += len;
		if ((size - off) < SECT_DATA_SIZE || len < SECT_DATA_SIZE) {	
			if ((ret = __call_rcb(lg, buf + skip, off - skip,
			    cb, cb_arg)) < 0)
				return ret;
			ret += skip;
			off -= ret;
			total_len += ret;
			memmove(buf, buf + ret, off);
			skip = 0;
		}
		expect_hdr = (len < SECT_DATA_SIZE) ? true : false;
	}
	ret = 0;
	if (off && (ret = __call_rcb(lg, buf + skip, off - skip,
	    cb, cb_arg)) < 0)
		return ret;
	ret += skip;
	total_len += ret;
	sec += total_len / SECT_DATA_SIZE;
	sec_off = total_len % SECT_DATA_SIZE;
	off = sec << SECT_SHFT;
	if (sec_off) {
		struct sect_dlm *dlm;

		if ((ret = __lg_read(lg, lg->sect, SECT_SIZE, off)))
			return ret;
		dlm = (lg->sect + SECT_HDR_OFFSET);
		__put_sect_coff(lg, dlm, sec_off);	
		memcpy(lg->sect + SECT_TLR_OFFSET, dlm, SECT_DLM_SIZE);
		if ((ret = __lg_write(lg, lg->sect, SECT_SIZE, off)))
			return ret;
		sec = sec + 1;
		off += SECT_SIZE;
	} 
	if (off < lg->size) 
		return __log_init(lg, sec);
	else if (sec_off) 
		return fsync(lg->fd);
	return 0;
}

void log_free(lm_log_t *lg)
{
	if (lg->sect)
		free(lg->sect);
	if (lg->zero_sect)
		free(lg->zero_sect);
	free(lg);
}

lm_log_t *
log_alloc(int fd, loff_t offset, size_t size, void *addr)
{
	lm_log_t *lg;

	assert((size & SECT_MASK) == 0);
	if (!(lg = malloc(sizeof (lm_log_t))))
		return ERR_PTR(-ENOMEM);
	if (!(lg->sect = malloc(SECT_SIZE))) {
		free(lg);
		return ERR_PTR(-ENOMEM);
	}
	if (!(lg->zero_sect = calloc(1, SECT_SIZE))) {
		free(lg->sect);
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
	lg->seqno = 0;
	lg->logid = 0;
	lg->commit_count = 0;
	lg->size = size;
	return lg;
}

static size_t
__recover(void *data, size_t size, int idx, void *arg)
{
	printf("hai %ld\n", size);
	return size;
}

int
lm_scan(lm_rcb_t rcb, void *arg)
{
	lm_log_t *lg, *flg, *tmp;
	void *buf;
	int ret = 0;

	list_for_each_entry(lg, &log_list, list) {
		if (ret = __lg_recover_seqno(lg))
			return ret;
	}
	list_for_each_entry_safe(lg, tmp, &log_list, list) {
		if (lg->seqno == ~0ULL)
			continue;
		list_del(&lg->list);
		list_for_each_entry(flg, &full_log_list, list) {
			assert(flg->seqno != lg->seqno);
			if (flg->seqno > lg->seqno) {
				list_add_tail(&lg->list, &flg->list);
				flg = NULL;
				break;
			}
		}
		if (flg) {
			list_add_tail(&lg->list, &full_log_list);
		}
	}
	if (!(buf = malloc(8192)))
		return -ENOMEM;
	list_for_each_entry(lg, &full_log_list, list) {
		if (log_seqno <= lg->seqno)
			log_seqno = lg->seqno + 1;
		if ((ret = __lg_recover(lg, buf, 8192, rcb, arg))) {
			free(buf);
			return ret;
		}
	}
	free(buf);
	list_for_each_entry(lg, &log_list, list) {
		if ((ret = __log_init(lg, 0)))
			return ret;
	}
	return ret;
}

void lm_system_exit()
{
	return;
}

int lm_system_init(int fd, loff_t off)
{
	lm_log_t *lg;
	int i, ret;
	pthread_t t;
/*
	if (LOG_ALIGN_SIZE > SECT_DLM_SIZE) {
		printf("LOG: Increase size of dlm->coff.\n");
		return -1;
	}
*/
	if (ret = io_setup(1024, &io_ctxt))
		return ret;
	pthread_create(&t, NULL, io_cb, NULL);
	pthread_create(&t, NULL, flush_thread, NULL);
	INIT_LIST_HEAD(&lbs_list);
	INIT_LIST_HEAD(&log_list);
	INIT_LIST_HEAD(&full_log_list);

	for (i = 0; i < TX_LOG_NBLKS; i++) {
		if (IS_ERR(lg = log_alloc(fd, off + (i << TX_LOG_BLK_SHFT),
		    TX_LOG_BLK_SIZE, NULL))) {
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
__log_recover(void *data, size_t size, void *arg)
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
	lr_hdr_t hdr;
	uint32_t n;
	uint32_t base;
	uint32_t num[0];
};

struct op {
	struct list_head list;
	lm_idx_t li;
	struct dop dop[0];
};

void *txer(void *arg)
{
	struct op *op;
	int n;
	int i;

	while (1) { 
		pthread_mutex_lock(&_lock);
		while (nnn > 10000000) 
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

		op->dop[0].hdr.len = sizeof(struct dop) + sizeof(uint32_t) * n;
		pthread_mutex_lock(&_lock);
		op->dop[0].hdr.lsn = __seqno++;
		list_add_tail(&op->list, &list);
		pthread_cond_broadcast(&_cond);
		nnn++;
		pthread_mutex_unlock(&_lock);
	}
	return NULL;
}

void *logger(void *arg)
{
	lm_idx_t li;
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

		op->li.lg1 = NULL;
		op->li.lg2 = NULL;
		ret = lm_write(op->dop, op->dop[0].hdr.len, &op->li); 
		assert(ret == 0);
//    		op->lg = lm_write(&li, (lg_rec_t *) op->dop);
    
		if ((random() % 100 == 0) && 
		    (ret = lm_commit(op->li.lg1,
			op->li.lg2 ? ~0ULL : op->li.eoff)) &&
		    op->li.lg2 &&
		    (ret = lm_commit(op->li.lg2, op->li.eoff))) {
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
		if (--nnn == 10000000)
			pthread_cond_broadcast(&ccond);
		pthread_mutex_unlock(&_lock);

		usleep(1);
		lm_log_put(op->li.lg1);
		if (op->li.lg2)
			lm_log_put(op->li.lg2);
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

	ret = lm_scan(__log_recover, NULL);
	assert(ret == 0);

	pthread_create(&t, NULL, txer, NULL);
	for (i = 0; i < 16; i++) 
		pthread_create(&t, NULL, logger, NULL);
	for (i = 0; i < 16; i++) 
		pthread_create(&t, NULL, releser, NULL);
	pthread_join(t, NULL);
}
#endif
