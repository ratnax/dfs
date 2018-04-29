#include "global.h"
#include "lm_ext.h"
#include "tx_int.h"

int
__recover_insert(struct pgop_insert *dop, size_t size)
{
	size_t len = dop->rec_len + sizeof(struct pgop_insert);

	if (len % 2) len++;
	eprintf("INSERT %d\n", dop->rec_len);
	if (size < sizeof(struct pgop_insert) || size < len)
		return 0;
	assert(dop->rec_len);
	return len;
}

int
__recover_delete(struct pgop_delete *dop, size_t size)
{
	size_t len = dop->rec_len + sizeof(struct pgop_delete);

	if (len % 2) len++;
	eprintf("DELETE\n");
	if (size < sizeof(struct pgop_delete) || size < len)
		return 0;
	return len;
}

int
__recover_replace(struct pgop_replace *dop, size_t size)
{
	size_t len = dop->key_len + dop->val_len + dop->rec_len +
	    sizeof(struct pgop_replace);

	if (len % 2) len++;
	eprintf("REPLACE\n");
	if (size < sizeof(struct pgop_replace) || size < len)
		return 0;
	return len;
}

int
__recover_split_left(struct pgop_split_left *dop, size_t size)
{
	size_t len = sizeof(struct pgop_split_left);

	if (len % 2) len++;
	eprintf("SPL_LEFT\n");
	if (size < sizeof(struct pgop_split_left) || size < len)
		return 0;
	return len;
}

int
__recover_split_right(struct pgop_split_right *dop, size_t size)
{
	size_t len = sizeof(struct pgop_split_right);

	if (len % 2) len++;
	eprintf("SPL_RIGHT\n");
	if (size < sizeof(struct pgop_split_right) || size < len)
		return 0;
	return len;
}

int
__recover_split_parent(struct pgop_split_parent *dop, size_t size)
{
	size_t len = sizeof(struct pgop_split_parent);

	if (len % 2) len++;
	eprintf("SPL_PARENT\n");
	if (size < sizeof(struct pgop_split_parent) || size < len)
		return 0;
	return len;
}

int
__recover_split_md(struct pgop_split_md *dop, size_t size)
{
	size_t len = sizeof(struct pgop_split_md);

	if (len % 2) len++;
	eprintf("SPL_MD\n");
	if (size < sizeof(struct pgop_split_md) || size < len)
		return 0;
	return len;
}

int
__recover_bmop(struct pgop_blkop *dop, size_t size)
{
	size_t len = sizeof(struct pgop_blkop);

	if (len % 2) len++;
	eprintf("BMOP\n");
	if (size < sizeof(struct pgop_blkop) || size < len)
		return 0;
	return len;
}

int
__recover_cmt_page(struct tx_commit_rec *cr, size_t size)
{
	size_t len = sizeof(struct tx_commit_rec) + PAGE_SIZE;

	if (len % 2) len++;
	eprintf("CMTPG\n");
	if (size < sizeof(struct tx_commit_rec) || size < len)
		return 0;
	return len;
}

int
__recover_cmt_txn(struct tx_commit_rec *cr, size_t size)
{
	size_t len = sizeof(struct tx_commit_rec);

	if (len % 2) len++;
	eprintf("CMTTXN\n");
	if (size < sizeof(struct tx_commit_rec) || size < len)
		return 0;
	return len;
}

static size_t
__recover(void *data, size_t size, void *arg)
{
	PG_DOP_HDR *hdr = data;
	size_t len, total_len = 0;

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

	if (ret = lm_scan(__recover, NULL))
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

