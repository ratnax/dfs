#include "global.h"

#define SECT_SHFT		(9)
#define SECT_SIZE		(1U << SECT_SHFT)
#define SECT_MASK		(SECT_SIZE - 1)

typedef uint8_t log_mrkr_t;
typedef uint8_t log_coff_t;

struct sect_dlm {
	log_mrkr_t  mrkr;
	log_coff_t  coff;
};

#define LOG_MRKR_SHFT		(sizeof (log_mrkr_t) << 3)
#define LOG_COFF_SHFT		(sizeof (log_coff_t) << 3)

#define LOG_ALIGN_SHFT		((SECT_SHFT > LOG_COFF_SHFT) ?		    \
				 (SECT_SHFT - LOG_COFF_SHFT) : 0)
#define LOG_ALIGN_SIZE		(1U << LOG_ALIGN_SHFT)
#define LOG_ALIGN_MASK		(LOG_ALIGN_SIZE - 1)

#define LOG_MRKR_INIT		((log_mrkr_t) 0)
#define LOG_MRKR_PSWITCH(m)	((log_mrkr_t) (~(m)))	/* partial switch */	
#define LOG_MRKR_FSWITCH(m)	((m) ^			/* full switch */   \
				(((log_mrkr_t) ~0) >> (LOG_MRKR_SHFT >> 1)))

#define SECT_DLM_SIZE		(sizeof (struct sect_dlm))

#define SECT_HDR_OFFSET		(0)
#define SECT_TLR_OFFSET		((SECT_SIZE - SECT_DLM_SIZE))
#define SECT_DATA_SIZE		(SECT_SIZE - 2 * SECT_DLM_SIZE)

#define LOG_MAX_IOV		(256)

struct log {
	loff_t	 off;			/* next log offset to write to */
	loff_t	 coff;			/* commit offset */
	loff_t	 base_offset;
	size_t	 size;
	uint8_t  mrkr;
	struct	 sect_dlm psh[2];	/* partial sector headers.  */
	struct	 sect_dlm pst[2];	/* partial sector trailers. */
	struct	 sect_dlm fsh;		/* full sector header */
	struct	 sect_dlm fst;		/* full sector trailer */
	uint8_t  pshi;			/* index into psh above */
	uint8_t  psti;			/* index into pst above */
	int	 fd;
	size_t	 lsh_iovidx;		/* last sector header iovidx */
	size_t	 fst_iovidx;		/* first sector trailer iovidx */	
	size_t	 iovmax;
	size_t	 iovidx;
	struct	 iovec *iov;
	void	*sect;
	void	*zero_sector;
	void	*mmaped_addr;
};

static loff_t
__encode_coff(struct log *lg, loff_t coff)
{
	if (lg->mrkr == LOG_MRKR_INIT)
		return coff >> LOG_ALIGN_SHFT;
	else
		return (SECT_SIZE - coff) >> LOG_ALIGN_SHFT;
}

static loff_t
__decode_coff(struct log *lg, loff_t coff)
{
	if (lg->mrkr == LOG_MRKR_INIT)
		return (coff << LOG_ALIGN_SHFT);
	else
		return (SECT_SIZE - (coff << LOG_ALIGN_SHFT));
}

static size_t
__log_sector(struct log *lg, void *data, size_t size)
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

size_t log_space_available(struct log *lg)
{
	size_t space_available;
	loff_t off;

	space_available = ((lg->size - lg->off) >> SECT_SHFT) * SECT_DATA_SIZE;
	if ((off = (lg->off & SECT_MASK))) 
		space_available += SECT_TLR_OFFSET - off;
	return space_available;
}

size_t __iov_needed(struct log *lg, size_t size)
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

size_t __iov_available(struct log *lg)
{
	return lg->iovmax - lg->iovidx;
}

int log_write(struct log *lg, void *data, size_t size)
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
	return 0;
}

static int
__log_flush(struct log *lg, struct iovec *iov, int cnt, loff_t off,
    size_t size)
{
	ssize_t bwrote;
	size_t len = 0;
	int i, ret;

	if (lg->mmaped_addr) {
		for (i = 0; i < cnt; i++) {
			memcpy(lg->mmaped_addr + off + len, iov[i].iov_base,
			    iov[i].iov_len);
			len += iov[i].iov_len;
		}
	} else {
		if ((size != (bwrote = pwritev(lg->fd, iov, cnt,
		    lg->base_offset + off))))
			return -EIO;
		if ((ret = fsync(lg->fd)))
			return ret;
	}
	return 0;
}

static size_t
__log_read(struct log *lg, void *data, size_t size, loff_t off)
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

static struct sect_dlm *__get_next_pst(struct log *lg)
{
	return &lg->pst[1 & lg->psti++];
}

static struct sect_dlm *__get_next_psh(struct log *lg)
{
	return &lg->psh[1 & lg->pshi++];
}

int __log_commit(struct log *lg)
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
			lg->iov[iovidx].iov_base = lg->zero_sector;
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
			lg->iov[iovidx].iov_base = lg->zero_sector;
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

	coff = coff & ~SECT_MASK;
	eprintf("flushing @ %ld %ld\n", coff, off - coff);
	return __log_flush(lg, lg->iov, iovidx, coff, off - coff);
}

int
log_commit(struct log *lg)
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
	} else if (lg->coff != lg->off) {
		if ((ret = __log_commit(lg))) 
			return ret;
	}

	lg->coff = lg->off;
	if (lg->off & SECT_MASK) {
		memcpy(lg->iov, &lg->iov[lg->lsh_iovidx],
		    sizeof (struct iovec) * (lg->iovidx - lg->lsh_iovidx));
		lg->iovidx = lg->iovidx - lg->lsh_iovidx;
	} else if (lg->off < lg->size) {
		hdr = __get_next_psh(lg);
		hdr->mrkr = lg->mrkr;
		hdr->coff = __encode_coff(lg, SECT_DLM_SIZE);

		lg->iov[0].iov_base = hdr;
		lg->iov[0].iov_len = SECT_DLM_SIZE;
		lg->iovidx = 1;
		lg->off += SECT_DLM_SIZE;
	}
	return 0;
}

static void
__init_fs_mrkrs(struct log *lg)
{
	lg->fsh.mrkr = lg->fst.mrkr = lg->mrkr;
	lg->fsh.coff = lg->fst.coff = __encode_coff(lg, SECT_TLR_OFFSET);
}

int log_finish(struct log *lg)
{
	size_t zero_len;
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	struct iovec iov;
	int ret;
	
	zero_len = log_space_available(lg);
	while (zero_len) {
		if (zero_len < SECT_SIZE) {
			if ((ret = log_write(lg, lg->zero_sector, zero_len)))
				return ret;
			zero_len = 0;
		} else {
			if ((ret = log_write(lg, lg->zero_sector, SECT_SIZE)))
				return ret;
			zero_len -= SECT_SIZE;
		}
	}
	if ((ret = log_commit(lg)))
		return ret;
	assert(lg->off == lg->coff);
	assert(lg->off == lg->size);

	hdr = (struct sect_dlm *) (lg->sect + SECT_HDR_OFFSET);
	tlr = (struct sect_dlm *) (lg->sect + SECT_TLR_OFFSET);

	hdr->mrkr = LOG_MRKR_FSWITCH(lg->mrkr);
	tlr->mrkr = lg->mrkr;
    	tlr->coff = hdr->coff = __encode_coff(lg, SECT_TLR_OFFSET);

	iov.iov_base = lg->sect;
	iov.iov_len = SECT_SIZE;
	if (ret = __log_flush(lg, &iov, 1, 0, SECT_SIZE))
		return ret;
	lg->mrkr = hdr->mrkr;
	lg->off = lg->coff = 0;
	lg->iovidx = 0;
	__init_fs_mrkrs(lg);
	return log_commit(lg);
}

static void
__recover_mrkr(struct log *lg, struct sect_dlm *hdr, struct sect_dlm *tlr)
{
	eprintf("in:%2x\n", hdr->mrkr);
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
			assert(0);
		}
	}

	eprintf("out:%2x\n", lg->mrkr);
	__init_fs_mrkrs(lg);
}

ssize_t
__recover_sector(struct log *lg, void *buf, loff_t sect)
{
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;

	if (SECT_SIZE != __log_read(lg, buf, SECT_SIZE, sect << SECT_SHFT))
		return -EIO;

	hdr = (struct sect_dlm *) (buf + SECT_HDR_OFFSET);
	tlr = (struct sect_dlm *) (buf + SECT_TLR_OFFSET); 

	if (sect == 0) 
		__recover_mrkr(lg, hdr, tlr);

	if (hdr->mrkr == tlr->mrkr)  
		return __decode_coff(lg, hdr->coff);
	else 
	 	return __decode_coff(lg, tlr->coff);
}

typedef size_t (*log_recover_cb_t)(void *buf, size_t size, void *arg);

int
log_recover(struct log *lg, void *buf, size_t size, log_recover_cb_t cb,
    void *cb_arg)
{
	loff_t off = 0, secoff;
	ssize_t len, sec;
	ssize_t ret_len;
	ssize_t total_len = 0;
	int err, i;

	for (i = 0; i < lg->size >> SECT_SHFT; i++) {
		if ((len = __recover_sector(lg, lg->sect, i)) < 0) {
			return len;
		}
		len -= SECT_DLM_SIZE;
		memcpy(buf + off, lg->sect + SECT_DLM_SIZE, len);
		off += len;

		if (len < SECT_DATA_SIZE || (size - off) < SECT_DATA_SIZE) {
			if ((ret_len = (*cb)(buf, off, cb_arg)) < 0) {
				return ret_len;
			}
			memcpy(buf, buf + ret_len, off - ret_len);
			off -= ret_len;

			total_len += ret_len;
			if (len < SECT_DATA_SIZE)
				break;
		}
	}
	if (off && ((ret_len = (*cb)(buf, off, cb_arg)) < 0)) 
		return ret_len;
    
	sec = total_len / SECT_DATA_SIZE;
	secoff = total_len % SECT_DATA_SIZE;
	lg->off = lg->coff = (sec << SECT_SHFT);
	if (err = log_commit(lg))
		return err;
	if (secoff) {
		if (SECT_SIZE != __log_read(lg, lg->sect, SECT_SIZE, sec)) 
			return -EIO;

		if (err = log_write(lg, lg->sect + SECT_DLM_SIZE, secoff))
			return err;

		if (err = log_commit(lg))
			return err;
	}
	return 0;
}

struct log *log_alloc(int fd, loff_t offset, size_t size, void *addr)
{
	struct log *lg;
	struct sect_dlm *hdr;

	if (!(lg = malloc(sizeof (struct log))))
		return ERR_PTR(-ENOMEM);
	if (!(lg->zero_sector = malloc(SECT_SIZE))) {
		free(lg);
		return ERR_PTR(-ENOMEM);
	}
	if (!(lg->sect = malloc(SECT_SIZE))) {
		free(lg->zero_sector);
		free(lg);
		return ERR_PTR(-ENOMEM);
	}
	if (!(lg->iov = malloc(sizeof (struct iovec) * LOG_MAX_IOV))) {
		free(lg->sect);
		free(lg->zero_sector);
		free(lg);
		return ERR_PTR(-ENOMEM);
	}
	lg->iovidx = 0;
	lg->iovmax = LOG_MAX_IOV;

	if (addr) {
		lg->mmaped_addr = addr;
		lg->fd = -1;
	} else {
		lg->fd = fd;
		lg->base_offset = offset;
		lg->mmaped_addr = NULL;
	}
	lg->size = size;
	lg->off = lg->coff = 0;
	lg->psti = lg->pshi = 0;
	lg->lsh_iovidx = 0;	
	lg->fst_iovidx = 0;		
	return lg;
}

static size_t
__log_recover(void *data, size_t size, void *arg)
{
	eprintf("hai %ld\n", size);
	return size;
}

int log_init(struct log *lg)
{
	void *sect;
	struct iovec iov;
	struct sect_dlm *hdr;
	struct sect_dlm *tlr;
	int ret = 0;
	int i;

	if (!(sect = calloc(1, SECT_SIZE)))
		return -ENOMEM;

	lg->mrkr = LOG_MRKR_INIT;

	hdr = sect + SECT_HDR_OFFSET;
	tlr = sect + SECT_TLR_OFFSET;

	tlr->mrkr = hdr->mrkr = LOG_MRKR_INIT;
	tlr->coff = hdr->coff = __encode_coff(lg, SECT_DLM_SIZE);

	iov.iov_base = sect;
	iov.iov_len = SECT_SIZE;
	for (i = 0; i < lg->size >> SECT_SHFT; i++)
		if (ret = __log_flush(lg, &iov, 1, i << SECT_SHFT, SECT_SIZE))
			break;
	free(sect);
	return ret;
}

int main(int argc, char **argv)
{
	struct log *lg;
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
	if (argv[2][0] == 'i' && (ret = log_init(lg)))
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

//	if (ret = log_commit(lg))
//		assert(0);
	return 0;
}
