#include "global.h"
#include "lm_int.h"

static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct lm_log_t **logs;
static int head, tail;

static loff_t
__encode_coff(lm_log_t *lg, loff_t coff)
{
	if (lg->mrkr == LOG_MRKR_INIT)
		return coff >> LOG_ALIGN_SHFT;
	else
		return (SECT_SIZE - coff) >> LOG_ALIGN_SHFT;
}

static loff_t
__decode_coff(lm_log_t *lg, loff_t coff)
{
	if (lg->mrkr == LOG_MRKR_INIT)
		return (coff << LOG_ALIGN_SHFT);
	else
		return (SECT_SIZE - (coff << LOG_ALIGN_SHFT));
}

static size_t
__log_sector(lm_log_t *lg, void *data, size_t size)
{
	size_t len;

	len = SECT_TLR_OFFSET - (lg->off & SECT_MASK);
	if (size >= len) 
		lg->iov[lg->iovidx].iov_len = len;
	else
		lg->iov[lg->iovidx].iov_len = size;
	lg->iov[lg->iovidx].iov_base = data;
	lg->off += lg->iov[lg->iovidx].iov_len;
	return lg->iov[lg->iovidx++].iov_len;
}

size_t
log_space_available(lm_log_t *lg)
{
	size_t space_available;
	loff_t off;

	space_available = ((lg->size - lg->off) >> SECT_SHFT) * SECT_DATA_SIZE;
	if ((off = (lg->off & SECT_MASK))) 
		space_available += SECT_TLR_OFFSET - off;
	return space_available;
}

static size_t 
__iov_needed(lm_log_t *lg, size_t size)
{
	size_t iov_needed = 0;
	loff_t off;

	if ((off = (lg->off & SECT_MASK))) {
		iov_needed += 2;
		if (size < (SECT_TLR_OFFSET - off)) {
			iov_needed += 1;
			size = 0;
		} else {
			size -= (SECT_TLR_OFFSET - off);
		}
	}
	iov_needed += size / SECT_DATA_SIZE * 3 + 1;
	if (size % SECT_DATA_SIZE)
		iov_needed += 4;
	return iov_needed;
}

static size_t 
__iov_available(lm_log_t *lg)
{
	return lg->iovmax - lg->iovidx;
}

static void
__log_write(lm_log_t *lg, void *data, size_t size)
{
	size_t len;
	size_t total;

	if ((lg->coff >> SECT_SHFT) == (lg->off >> SECT_SHFT)) {
		len = __log_sector(lg, data, size);
		lg->fst_iovidx = lg->iovidx;
	} else {
		len = __log_sector(lg, data, size);
	}
	while (size -= len) {
		lg->iov[lg->iovidx].iov_base = &lg->fst;
		lg->iov[lg->iovidx].iov_len = SECT_DLM_SIZE;
		lg->off += SECT_DLM_SIZE;
		lg->iovidx++;

		lg->iov[lg->lsh_iovidx].iov_base = &lg->fsh;
		lg->iov[lg->lsh_iovidx].iov_len = SECT_DLM_SIZE;
		lg->lsh_iovidx = lg->iovidx++;
		lg->off += SECT_DLM_SIZE;

		len = __log_sector(lg, data + len, size);
	}
}

int
log_writev(lm_log_t *lg, struct iovec *iov, size_t iovcnt, size_t size)
{
	size_t len = 0;
	size_t iov_needed;
	int ret, i;

	if (log_space_available(lg) < size)
		return -ENOSPC;
	if ((iov_needed = iovcnt + __iov_needed(lg, size)) > 
	    __iov_available(lg) && (ret = log_commit(lg)))
		return ret;
	if (iov_needed > __iov_available(lg))
		return -ENOSPC;
	for (i = 0; i < iovcnt; i++)
		__log_write(lg, iov[i].iov_base, iov[i].iov_len);
	return 0;
}

int
log_write(lm_log_t *lg, void *data, size_t size)
{
	size_t len = 0;
	size_t iov_needed;
	int ret;

	if (log_space_available(lg) < size)
		return -ENOSPC;
	if ((iov_needed = __iov_needed(lg, size)) > __iov_available(lg) &&
	    (ret = log_commit(lg)))
		return ret;
	if (iov_needed > __iov_available(lg))
		return -ENOSPC;
	__log_write(lg, data, size);
	return 0;
}

bool lm_isfull(void)
{
	if (head < tail) 
		return (tail - head) < 10; //(TX_LOG_NBLKS / 2);
	else
		return (head - tail) > 10; //(TX_LOG_NBLKS / 2);
}

void kkk(void) {}
lm_log_t *
lm_writev(struct iovec *iov, size_t iovcnt, size_t size)
{
	lm_log_t *lg;
	int ret;

	do {
		lg = logs[head];

		if (-ENOSPC == (ret = log_writev(lg, iov, iovcnt, size))) {
			kkk();
			if ((ret = log_commit(lg)))
				return ERR_PTR(ret);
			if (((head + 1) % TX_LOG_NBLKS) != tail)
				head = (head + 1) % TX_LOG_NBLKS;
			else
				break;
		} else {
			if (!ret) {
				lg->commit_count++;	
				return lg;
			}
			return ERR_PTR(ret);
		}

	} while (1);
	return ERR_PTR(-ENOSPC);
}

lm_log_t *
lm_write(void *data, size_t size)
{
	lm_log_t *lg;
	int ret;

	do {
		lg = logs[head];

		if (-ENOSPC == (ret = log_write(lg, data, size))) {
			kkk();
			if ((ret = log_commit(lg)))
				return ERR_PTR(ret);
			if (((head + 1) % TX_LOG_NBLKS) != tail)
				head = (head + 1) % TX_LOG_NBLKS;
			else
				break;
		} else {
			if (!ret) {
				lg->commit_count++;	
				return lg;
			}
			return ERR_PTR(ret);
		}

	} while (1);
	return ERR_PTR(-ENOSPC);
}

int 
lm_commit(void)
{
	return log_commit(logs[head]);
}

int
log_put(lm_log_t *lg)
{
	int ret = 0;

	--lg->commit_count;
	do {
		if (logs[tail]->commit_count)
			break;
		if ((ret = log_finish(logs[tail])))
			return ret;
		if (tail == head) 
			break;
		tail = (tail + 1) % TX_LOG_NBLKS; 
	} while (1);
	return ret;
}

static int
__log_flush(lm_log_t *lg, struct iovec *iov, int cnt, loff_t off, size_t size,
    bool sync)
{
	ssize_t bwrote;
	size_t len = 0;
	int i, ret;

	printf("Flushing @ %ld %ld\n", off, size);
	if (lg->mmaped_addr) {
		for (i = 0; i < cnt; i++) {
			memcpy(lg->mmaped_addr + off + len, iov[i].iov_base,
			    iov[i].iov_len);
			len += iov[i].iov_len;
		}
	} else {
		if ((size != (bwrote = pwritev(lg->fd, iov, cnt,
		    lg->base_offset + off)))) {
			assert(0);
			return -EIO;
			}
		if (sync && (ret = fsync(lg->fd)))
			return ret;
	}
	return 0;
}

static size_t
__log_read(lm_log_t *lg, void *data, size_t size, loff_t off)
{
	size_t bread;
	size_t len = MIN(size, lg->size - off);

	if (lg->mmaped_addr) {
		memcpy(data, lg->mmaped_addr + off, len);
	} else {
		if ((bread = pread(lg->fd, data, len,
		    lg->base_offset + off)) != len)
			return -EIO;
	}
	return len;
}

static struct sect_dlm *
__get_next_pst(lm_log_t *lg)
{
	return &lg->pst[1 & lg->psti++];
}

static struct sect_dlm *
__get_next_psh(lm_log_t *lg)
{
	return &lg->psh[1 & lg->pshi++];
}

static int
__log_commit(lm_log_t *lg)
{
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	loff_t coff	= lg->coff;
	loff_t off	= lg->off;
	ssize_t zero_len;
	int ret, iovidx	= lg->iovidx;
	int tlr_iovidx;

	hdr = lg->iov[0].iov_base;
	tlr = __get_next_pst(lg);

	if (coff & SECT_MASK)
		hdr->mrkr = LOG_MRKR_PSWITCH(hdr->mrkr);
	tlr->mrkr = hdr->mrkr;
	    
	if ((off >> SECT_SHFT) == (coff >> SECT_SHFT)) {
		hdr->coff = tlr->coff = __encode_coff(lg, off & SECT_MASK);
		if ((zero_len = SECT_TLR_OFFSET - (off & SECT_MASK))) {
			lg->iov[iovidx].iov_base = lg->zero_sect;
			lg->iov[iovidx++].iov_len = zero_len;
			off += zero_len;
		} else {
			lg->off += SECT_DLM_SIZE;
		}
		lg->iov[iovidx].iov_base = tlr;
		lg->iov[iovidx++].iov_len = SECT_DLM_SIZE;
		off += SECT_DLM_SIZE;
	} else {
		tlr->coff = hdr->coff = __encode_coff(lg, SECT_TLR_OFFSET);
		lg->iov[lg->fst_iovidx].iov_base = tlr;
		lg->iov[lg->fst_iovidx].iov_len = SECT_DLM_SIZE;
	}
	if (off & SECT_MASK) {
		hdr = __get_next_psh(lg);
		tlr = __get_next_pst(lg);

		hdr->mrkr = tlr->mrkr = lg->mrkr; 
		tlr->coff = hdr->coff = __encode_coff(lg, off & SECT_MASK);

		lg->iov[lg->lsh_iovidx].iov_base = hdr;
		lg->iov[lg->lsh_iovidx].iov_len = SECT_DLM_SIZE;
		if ((zero_len = SECT_TLR_OFFSET - (off & SECT_MASK))) {
			lg->iov[iovidx].iov_base = lg->zero_sect;
			lg->iov[iovidx++].iov_len = zero_len;
			off += zero_len;
		} else {
			lg->off += SECT_DLM_SIZE;
		}
		lg->iov[iovidx].iov_base = tlr;
		lg->iov[iovidx++].iov_len = SECT_DLM_SIZE;

		off = off + SECT_DLM_SIZE;
	}
	assert ((off & SECT_MASK) == 0);
	assert(iovidx <= lg->iovmax);

	coff = coff & ~SECT_MASK;
	return __log_flush(lg, lg->iov, iovidx, coff, off - coff, true);
}

int
log_commit(lm_log_t *lg)
{
	struct sect_dlm *hdr;
	int ret;

	if (lg->coff & SECT_MASK) {
		if (lg->coff == lg->off)
			return 0;
		if ((ret = __log_commit(lg)))
			return ret;
	} else if (lg->coff + SECT_DLM_SIZE == lg->off) {
		return 0;
	} else if (lg->coff != lg->off && (ret = __log_commit(lg))) {
		return ret;
	}
	lg->coff = lg->off;
	if (lg->off & SECT_MASK) {
		int i;
		void *sect = lg->sect;

		memmove(lg->iov, &lg->iov[lg->lsh_iovidx],
		    sizeof (struct iovec) * (lg->iovidx - lg->lsh_iovidx));
		lg->iovidx = lg->iovidx - lg->lsh_iovidx;
		lg->lsh_iovidx = 0;

		for (i = 1; i < lg->iovidx; i++) {
			memmove(sect, lg->iov[i].iov_base, lg->iov[i].iov_len);
			lg->iov[i].iov_base = sect;
			sect += lg->iov[i].iov_len;
		}
		assert(sect < lg->sect + SECT_SIZE);
	} else if (lg->off < lg->size) {
		hdr = __get_next_psh(lg);
		hdr->mrkr = lg->mrkr;
		hdr->coff = __encode_coff(lg, SECT_DLM_SIZE);

		lg->lsh_iovidx = 0;
		lg->iov[0].iov_base = hdr;
		lg->iov[0].iov_len = SECT_DLM_SIZE;
		lg->iovidx = 1;
		lg->off += SECT_DLM_SIZE;
	}
	return 0;
}

static void
__init_fs_mrkrs(lm_log_t *lg)
{
	lg->fsh.mrkr = lg->fst.mrkr = lg->mrkr;
	lg->fsh.coff = lg->fst.coff = __encode_coff(lg, SECT_TLR_OFFSET);
}

int
log_finish(lm_log_t *lg)
{
	size_t zero_len;
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	struct iovec iov;
	int ret;
	
	if ((ret = log_commit(lg)))
		return ret;
	zero_len = log_space_available(lg);
	while (zero_len) {
		if (zero_len < SECT_SIZE) {
			if ((ret = log_write(lg, lg->zero_sect, zero_len))){
				assert(0);
				return ret;
			}
			zero_len = 0;
		} else {
			if ((ret = log_write(lg, lg->zero_sect, SECT_SIZE))) {
				assert(0);
				return ret;
		}
			zero_len -= SECT_SIZE;
		}
	}
	if ((ret = log_commit(lg)))
		return ret;
	assert(lg->off == lg->coff);
	assert(lg->off == lg->size);

	hdr = (struct sect_dlm *) (lg->zero_sect + SECT_HDR_OFFSET);
	tlr = (struct sect_dlm *) (lg->zero_sect + SECT_TLR_OFFSET);

	hdr->mrkr = LOG_MRKR_FSWITCH(lg->mrkr);
	tlr->mrkr = lg->mrkr;
    	tlr->coff = hdr->coff = __encode_coff(lg, SECT_TLR_OFFSET);

	iov.iov_base = lg->zero_sect;
	iov.iov_len = SECT_SIZE;
	if (ret = __log_flush(lg, &iov, 1, 0, SECT_SIZE, true))
		return ret;
	lg->mrkr = hdr->mrkr;
	lg->off = lg->coff = 0;
	lg->iovidx = 0;
	__init_fs_mrkrs(lg);
	return log_commit(lg);
}

static int
__log_init(lm_log_t *lg, loff_t start_sect)
{
	struct iovec iov;
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	int ret = 0;
	int i;

	hdr = lg->zero_sect + SECT_HDR_OFFSET;
	tlr = lg->zero_sect + SECT_TLR_OFFSET;

	tlr->mrkr = hdr->mrkr = LOG_MRKR_FSWITCH(lg->mrkr);
	tlr->coff = hdr->coff = __encode_coff(lg, SECT_DLM_SIZE);

	iov.iov_base = lg->zero_sect;
	iov.iov_len = SECT_SIZE;
	for (i = start_sect; i < (lg->size >> SECT_SHFT); i++) {
		if ((ret = __log_flush(lg, &iov, 1, i << SECT_SHFT,
		    SECT_SIZE, false)))
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
	__init_fs_mrkrs(lg);
	return 0;
}

static ssize_t
__recover_sector(lm_log_t *lg, void *buf, loff_t sect)
{
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	int ret;

	if (SECT_SIZE != __log_read(lg, buf, SECT_SIZE, sect << SECT_SHFT))
		return -EIO;

	hdr = (struct sect_dlm *) (buf + SECT_HDR_OFFSET);
	tlr = (struct sect_dlm *) (buf + SECT_TLR_OFFSET); 

	if (sect == 0 && (ret = __recover_mrkr(lg, hdr, tlr))) 
		return ret;

	if (hdr->mrkr == tlr->mrkr)  
		return __decode_coff(lg, hdr->coff);
	else 
	 	return __decode_coff(lg, tlr->coff);
}

int
log_recover(lm_log_t *lg, void *buf, size_t size, lm_rcb_t cb, void *cb_arg)
{
	loff_t off = 0, sec_off;
	ssize_t len, sec;
	ssize_t ret_len;
	ssize_t total_len = 0;
	int err, i;

	for (i = 0; i < lg->size >> SECT_SHFT; i++) {
		if ((len = __recover_sector(lg, lg->sect, i)) < 0) 
			return len;
		len -= SECT_DLM_SIZE;
		memmove(buf + off, lg->sect + SECT_DLM_SIZE, len);
		off += len;
		if ((size - off) < SECT_DATA_SIZE) {
			if ((ret_len = (*cb)(buf, off, cb_arg)) < 0) 
				return ret_len;
			memmove(buf, buf + ret_len, off - ret_len);
			off -= ret_len;
			total_len += ret_len;
		}
		if (len < SECT_DATA_SIZE)
			break;
	}
	if (off && ((ret_len = (*cb)(buf, off, cb_arg)) < 0)) 
		return ret_len;
	sec = total_len / SECT_DATA_SIZE;
	sec_off = total_len % SECT_DATA_SIZE;
	lg->off = lg->coff = (sec << SECT_SHFT);
	if ((err = log_commit(lg)))
		return err;
	if (sec_off) {
		if (SECT_SIZE != __log_read(lg, lg->sect, SECT_SIZE, sec)) 
			return -EIO;
		if ((err = log_write(lg, lg->sect + SECT_DLM_SIZE, sec_off)))
			return err;
		if ((err = log_commit(lg)))
			return err;
	}
	return __log_init(lg, sec + 1);
}

void log_free(lm_log_t *lg)
{
	if (lg->zero_sect) free(lg->zero_sect);
	if (lg->sect) free(lg->sect);
	if (lg->iov) free(lg->iov);
	free(lg);
}

lm_log_t *
log_alloc(int fd, loff_t offset, size_t size, void *addr)
{
	lm_log_t *lg;
	struct sect_dlm *hdr;

	if (!(lg = malloc(sizeof (lm_log_t))))
		return ERR_PTR(-ENOMEM);
	if (!(lg->zero_sect = malloc(SECT_SIZE))) {
		free(lg);
		return ERR_PTR(-ENOMEM);
	}
	if (!(lg->sect = malloc(SECT_SIZE))) {
		free(lg->zero_sect);
		free(lg);
		return ERR_PTR(-ENOMEM);
	}
	if (!(lg->iov = malloc(sizeof (struct iovec) * LOG_MAX_IOV))) {
		free(lg->sect);
		free(lg->zero_sect);
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
	lg->iovidx = 0;
	lg->iovmax = LOG_MAX_IOV;
	lg->size = size;
	lg->off = lg->coff = 0;
	lg->psti = lg->pshi = 0;
	lg->lsh_iovidx = 0;	
	lg->fst_iovidx = 0;		
	lg->commit_count = 0;
	__init_fs_mrkrs(lg);
	return lg;
}

static size_t
__recover(void *data, size_t size, void *arg)
{
	printf("hai %ld\n", size);
	return size;
}

int
lm_scan(lm_rcb_t rcb, void *arg)
{
	int i, ret;
	void *buf;

	if (!(buf = malloc(8192)))
		return -ENOMEM;
	for (i = 0; i < TX_LOG_NBLKS; i++) {
		eprintf("recovering log %d\n", i);
		if ((ret = log_recover(logs[i], buf, 8192, rcb, arg))) {
			if (ret == -ENXIO) {
				if ((ret = log_finish(logs[i]))) {
					free(buf);
					return ret;
				}
			} else { 
				free(buf);
				return ret;
			}
		}
	}
	free(buf);
	return 0;
}

void lm_system_exit()
{
	assert(head == tail);
	assert(logs[head]->commit_count == 0);
}

int lm_system_init(int fd, loff_t off)
{
	lm_log_t *lg;
	int i, ret;

	if (!(logs = calloc(TX_LOG_NBLKS, sizeof(lm_log_t *))))
		return -ENOMEM;
	for (i = 0; i < TX_LOG_NBLKS; i++) {
		if (IS_ERR(lg = log_alloc(fd, 
		    off + (i << TX_LOG_BLK_SHFT), TX_LOG_BLK_SIZE,
		    NULL))) {
			free(logs);
	    		return PTR_ERR(lg);
		}
		logs[i] = lg;
	}
	head = 0;
	tail = 0;
	return 0;
}

long
lm_mkfs(int fd, loff_t off)
{
	lm_log_t *lg;
	int i, ret;

	for (i = 0; i < TX_LOG_NBLKS; i++) {
		if (IS_ERR(lg = log_alloc(fd, off + (i << TX_LOG_BLK_SHFT),
		    TX_LOG_BLK_SIZE, NULL))) {
	    		return PTR_ERR(lg);
		}
		if ((ret = log_finish(lg)))
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

int main(int argc, char **argv)
{
	lm_log_t *lg;
	void *addr;
	int i, ret;
	int fd;
	void *buf;

	if (LOG_ALIGN_SIZE > sizeof (struct sect_dlm)) {
		printf("LOG: Increase size of dlm->coff.\n");
		return -1;
	}
	if (!(buf = malloc(4 * 1024)))
		return -ENOMEM;
	if ((fd = open(argv[1], O_RDWR)) <= 0)
		return fd;
	if ((ret = ftruncate(fd, 4 * 1024 * 1024)))
		return ret;
	if (MAP_FAILED == (addr = mmap(NULL, 4 * 1024 * 1024,
	    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)))
		return -1;
	if (!(lg = log_alloc(-1, 0, 1024 * 1024, addr)))
		return PTR_ERR(lg);
	if (argv[2][0] == 'i' && (ret = log_finish(lg)))
		return ret;
	if ((ret = log_recover(lg, buf, 4 * 1024, __log_recover, NULL)))
		return ret;
	for (i = 0; i < atoi(argv[3]); i++) {
		char buf[100];

		if (ret = log_write(lg, buf, 100))
			assert(0);
		if (i % 10 == 9 && (ret = log_commit(lg)))
			assert(0);
	}
	if (ret = log_finish(lg))
		return ret;

	for (i = 0; i < atoi(argv[3]) / 2; i++) {
		char buf[100];

		if (ret = log_write(lg, buf, 100))
			assert(0);
		if (i % 10 == 9 && (ret = log_commit(lg)))
			assert(0);
	}

	if ((ret = log_commit(lg)))
		return ret;
	return 0;
}
#endif
