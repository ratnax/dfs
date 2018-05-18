#include "global.h"
#include "lm_ext.h"
#include "tx_int.h"
#include "pm_int.h"

int
__recover_insert(struct pgop_insert *dop, size_t size)
{
	size_t len = dop->rec_len + sizeof(struct pgop_insert);

	if (len % 2) len++;
	eprintf("INSERT %d %lx\n", dop->rec_len, dop->lsn);
	if (size < sizeof(struct pgop_insert) || size < len)
		return 0;

//	len = tx_recover_insert(dop);
	return len;
}

int
__recover_delete(struct pgop_delete *dop, size_t size)
{
	size_t len = dop->rec_len + sizeof(struct pgop_delete);

	if (len % 2) len++;
	eprintf("DELETE %lx\n", dop->lsn);
	if (size < sizeof(struct pgop_delete) || size < len)
		return 0;
//	len = tx_recover_delete(dop);
	return len;
}

int
__recover_replace(struct pgop_replace *dop, size_t size)
{
	size_t len = dop->key_len + dop->val_len + dop->rec_len +
	    sizeof(struct pgop_replace);

	if (len % 2) len++;
	eprintf("REPLACE %lx\n", dop->lsn);
	if (size < sizeof(struct pgop_replace) || size < len)
		return 0;
//	len = tx_recover_replace(dop);
	return len;
}

int
__recover_split_left(struct pgop_split_left *dop, size_t size)
{
	size_t len = sizeof(struct pgop_split_left);

	if (len % 2) len++;
	eprintf("SPL_LEFT %lx\n", dop->lsn);
	if (size < sizeof(struct pgop_split_left) || size < len)
		return 0;
//	len = tx_recover_split_left(dop);
	return len;
}

int
__recover_split_right(struct pgop_split_right *dop, size_t size)
{
	size_t len = sizeof(struct pgop_split_right);

	if (len % 2) len++;
	eprintf("SPL_RIGHT %lx\n", dop->lsn);
	if (size < sizeof(struct pgop_split_right) || size < len)
		return 0;
//	len = tx_recover_split_right(dop);
	return len;
}

int
__recover_split_parent(struct pgop_split_parent *dop, size_t size)
{
	size_t len = sizeof(struct pgop_split_parent);

	if (len % 2) len++;
	eprintf("SPL_PARENT %lx\n", dop->lsn);
	if (size < sizeof(struct pgop_split_parent) || size < len)
		return 0;
//	len = tx_recover_split_parent(dop);
	return len;
}

int
__recover_split_md(struct pgop_split_md *dop, size_t size)
{
	size_t len = sizeof(struct pgop_split_md);

	if (len % 2) len++;
	eprintf("SPL_MD %lx\n", dop->lsn);
	if (size < sizeof(struct pgop_split_md) || size < len)
		return 0;
//	len = tx_recover_split_md(dop);
	return len;
}

int
__recover_bmop(struct pgop_blkop *dop, size_t size)
{
	size_t len = sizeof(struct pgop_blkop);

	if (len % 2) len++;
	eprintf("BMOP %lx\n", dop->lsn);
	if (size < sizeof(struct pgop_blkop) || size < len)
		return 0;
//	len = tx_recover_bmop(dop);
	return len;
}

int
__recover_cmt_page(struct tx_commit_rec *cr, size_t size)
{
	size_t len = sizeof(struct tx_commit_rec) + PAGE_SIZE;

	if (len % 2) len++;
	eprintf("CMTPG %lx\n", cr->pgno);
	if (size < sizeof(struct tx_commit_rec) || size < len)
		return 0;
//	len = tx_recover_cmd_page(cr);
	return len;
}

int
__recover_cmt_txn(struct tx_commit_rec *cr, size_t size)
{
	size_t len = sizeof(struct tx_commit_rec);

	if (len % 2) len++;
	eprintf("CMTTXN %lx\n", cr->txid);
	if (size < sizeof(struct tx_commit_rec) || size < len)
		return 0;
//	len = tx_recover_cmt_txn(cr);
	return len;
}

struct rm_data_t {
	int pass;
	uint64_t min_lsn;
	uint64_t max_lsn;
	int head;
	int tail;
};

static size_t
__recover(void *data, size_t size, int idx, void *arg)
{
	PG_DOP_HDR *hdr = data;
	size_t len, total_len = 0;
	struct rm_data_t *rmd = (struct rm_data_t *) arg;

	if (hdr->type >= PGOP_INSERT && hdr->type < PGOP_MAXOP) {
		if (rmd->pass == 1) {
			if (rmd->min_lsn > hdr->lsn) {
				rmd->min_lsn = hdr->lsn;
				rmd->tail = idx;
			}
			if (rmd->max_lsn < hdr->lsn) {
				rmd->max_lsn = hdr->lsn;
				rmd->head = idx;
			}
			eprintf("%d %d %d\n", idx, rmd->head, rmd->tail);
			return -EAGAIN;
		}
	}

	do {
	switch(hdr->type) {
	case PGOP_NOP:
		eprintf("NOP\n");
		len = size;
		break;
	case PGOP_INSERT:
		if ((len = __recover_insert((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_DELETE:
		if ((len = __recover_delete((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_REPLACE:
		if ((len = __recover_replace((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_SPLIT_OLD:
		break;
	case PGOP_SPLIT_LEFT:
		if ((len = __recover_split_left((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_SPLIT_RIGHT:
		if ((len = __recover_split_right((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_SPLIT_PARENT:
		if ((len = __recover_split_parent((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_SPLIT_MD:
		if ((len = __recover_split_md((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_BLKSET:
		if ((len = __recover_bmop((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_BLKRESET:
		if ((len = __recover_bmop((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_COMMIT_PAGE:
		if ((len = __recover_cmt_page((void *) hdr, size)) < 0)
			return len;
		break;
	case PGOP_COMMIT_TXN:
		if ((len = __recover_cmt_txn((void *) hdr, size)) < 0)
			return len;
		break;
	default:
		assert(0);
	}
	hdr = ((void *) hdr) + len;
	size -= len;
	total_len += len;
	eprintf("%ld %ld\n", size, len);
	} while (len && size);
	return total_len;
}

int
rm_recover(void)
{
	int ret;
	struct rm_data_t rmd;

	rmd.head = rmd.tail = 0;
	rmd.min_lsn = ~0ULL;
	rmd.max_lsn = 0;
	rmd.pass = 1;

	if (ret = lm_scan(__recover, &rmd))
		return ret;

	lm_set_valid_range(rmd.head, rmd.tail);

	rmd.pass = 2;
	if (ret = lm_scan(__recover, &rmd))
		return ret;
	return 0;
}

void rm_system_exit(void)
{
}

int rm_system_init(int fd)
{
	return 0;
}

