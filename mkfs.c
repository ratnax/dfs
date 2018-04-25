#include "global.h"
#include "ondisk_format.h"
#include "lm_ext.h"
#include "bm_ext.h"
#include "bt_ext.h"

int main(int argc, char **argv)
{
	int fd;
	int lm_npgs;
	int bm_npgs;
	int err;
	struct super_block sb;

	if ((fd = open(argv[1], O_RDWR|O_CREAT, 0755)) <= 0) {
		fprintf(stderr, "Open failed (%s)\n", strerror(errno));
		return (-errno);
	}
	
	sb.magic = SB_MAGIC;
	sb.bm_map_pgno = BM_MAP_PGNO;
	if ((sb.bm_map_npgs = bm_mkfs(fd)) < 0)
		return err;
	sb.lm_log_off = (BM_MAP_PGNO + sb.bm_map_npgs) << PAGE_SHFT; 
	if ((sb.lm_log_npgs = lm_mkfs(fd, sb.lm_log_off)) <= 0)
		return err;
	if ((err = bt_mkfs(fd, sb.bm_map_npgs + sb.lm_log_npgs + BM_MAP_PGNO)))
		return err;

	if (sizeof(struct super_block) != pwrite(fd, &sb,
	    sizeof(struct super_block), 0))
		return -EIO;
	if ((err = fsync(fd)))
		return err;
	return 0;
}
