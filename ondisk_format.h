#ifndef __ONDISK_FORMAT_H__
#define __ONDISK_FORMAT_H__

#define TOTAL_SPACE	(1024 * 1024 * 1024)
#define TX_LOG_SPACE	(32 * 1024 * 1024)

#define SB_PGNO		(0)
#define BT_MD_PGNO	(1)
#define BM_MAP_PGNO	(2)

#define BM_PREMAP_PGS	(2)
#define BM_POSTMAP_PGS	(1 + (TX_LOG_SPACE >> 12)) /* "1" for tree root page */

#define SB_MAGIC	(*(uint64_t *) "SUPERBLK")
struct super_block {
	uint64_t magic;
	uint64_t bt_md_pgno;
	uint64_t bm_map_pgno;
	uint64_t bm_map_npgs;
	uint64_t lm_log_off;
	uint64_t lm_log_npgs;
};
#endif
