#include "global.h"
#include "list.h"
#include "mm_ext.h"

#define MEM_BLK_SHFT 16
#define MEM_BLK_SIZE (1 << MEM_BLK_SHFT)

typedef enum {INUSE, UNUSABLE, TOUSE} mb_state_t;

struct ele_hdr {
	uint32_t free:1;
	uint32_t size:31; /* ele size, sizeof (ele_hdr) excluded */
};

struct mem_blk {
	mb_state_t	state;
	void		*head;
	void		*tail;
	void		*last;
	void		*frst;
	struct list_head list;
};

static struct list_head inuse_list;
static struct list_head unuse_list;
static struct list_head touse_list;
static size_t mb_rsvd_size;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static bool __isfull(mm_blk_t *mb)
{
	struct ele_hdr *hdr;

	if (mb->head <= mb->tail) {
		if (mb->head - mb->frst >= mb_rsvd_size)
			return false;
		if (mb->last - mb->tail + sizeof (struct ele_hdr) <
		    mb_rsvd_size)
			return true;
		printf("%p %d %d -> ", mb, mb->head - mb->frst, 
		    mb->tail - mb->frst); 
		hdr = mb->head = mb->last - sizeof (struct ele_hdr);
		printf("%d %d\n", mb, mb->head - mb->frst, mb->tail - mb->frst); 
		hdr->free = 0;
		hdr->size = 0;
	} else { 
		if ((mb->head - mb->tail + sizeof(struct ele_hdr)) <
		    mb_rsvd_size)
			return true;
	}
	return false;
}

void mm_unreserve(mm_blk_t *mb)
{
	struct ele_hdr *hdr = mb->head;

	assert(mb->state == INUSE);
	assert(hdr->size < mb_rsvd_size - sizeof(struct ele_hdr));
	mb->head -= hdr->size;
	hdr = mb->head = mb->head - sizeof (struct ele_hdr);
	printf("%p unreserve %d %d\n", mb, mb->head - mb->frst,
	    mb->tail - mb->frst); 
	hdr->free = 0;
	hdr->size = 0;
	assert(mb->head >= mb->frst);

	pthread_mutex_lock(&mutex);
	list_del(&mb->list);
	if (__isfull(mb)) {
		mb->state = UNUSABLE;
		list_add(&mb->list, &unuse_list);
	} else {
		mb->state = TOUSE;
		list_add(&mb->list, &touse_list);
	}
	pthread_mutex_unlock(&mutex);
}

mm_blk_t *mm_reserve(void)
{
	struct mem_blk *new_mb = NULL, *mb;
	struct ele_hdr *hdr;

	pthread_mutex_lock(&mutex);
	while (list_empty(&touse_list)) {
		if (!new_mb) {
		    	pthread_mutex_unlock(&mutex);
			if (!(new_mb = malloc(MEM_BLK_SIZE)))
				return ERR_PTR(-ENOMEM);
			pthread_mutex_lock(&mutex);
		} else {
			list_add(&new_mb->list, &inuse_list);
			new_mb->state = INUSE;
			pthread_mutex_unlock(&mutex);

			new_mb->frst = new_mb + 1;
			new_mb->last = ((void *) new_mb) + MEM_BLK_SIZE;
			new_mb->head = new_mb->last - sizeof(struct ele_hdr);
			new_mb->tail = new_mb->head;
			hdr = new_mb->head;
			hdr->free = 0;
			hdr->size = 0;
			printf("%p reserve new\n");
			return new_mb;
		}
	} 
	mb = list_first_entry(&touse_list, struct mem_blk, list);
	list_del(&mb->list);
	list_add(&mb->list, &inuse_list);
	mb->state = INUSE;
	printf("%p reserve %d %d\n", mb, mb->head - mb->frst,
	    mb->tail - mb->frst); 
	pthread_mutex_unlock(&mutex);
	if (new_mb)
		free(new_mb);
	return mb;
}

void mm_free(mm_blk_t *mb, void *p, size_t size)
{
	struct ele_hdr *hdr = p + size;

	printf("%p free %d %d free from %d to %d hsize %d\n", mb,
	    mb->head - mb->frst, mb->tail - mb->frst, p - mb->frst,
	    p + size - mb->frst, hdr->size);

	hdr->free = 1;
	pthread_mutex_lock(&mutex);
	hdr = mb->tail;
	while (hdr->free) {
		printf("%p free loop2 %d %d from %d to %d bit:%d " 
		    "hsize %d\n", mb, mb->head - mb->frst, 
		    mb->tail - mb->frst,
		    mb->tail - mb->frst + sizeof (struct ele_hdr),
		    mb->tail - mb->frst - hdr->size, hdr->free,
		    hdr->size);
		hdr = mb->tail = mb->tail - hdr->size - sizeof (struct ele_hdr);

		if (mb->tail < mb->head && 
		    mb->tail - mb->frst < mb_rsvd_size) {
			hdr = mb->tail = mb->last - sizeof (struct ele_hdr);
			printf("%p free loop1 %d %d bit:%d hsize %d\n", mb,
			    mb->head - mb->frst, mb->tail - mb->frst, hdr->free,
			    hdr->size);
		}
	}
	if (mb->state == UNUSABLE && !__isfull(mb)) {
		list_del(&mb->list);
		list_add(&mb->list, &touse_list);
		mb->state = TOUSE;
	}
	pthread_mutex_unlock(&mutex);
}

void *mm_alloc(mm_blk_t *mb, size_t size)
{
	struct ele_hdr *hdr = mb->head;

	assert(mb->state == INUSE);
	hdr->size += size;

	printf("%p alloc %d %d size %d t: %d\n", mb, mb->head - mb->frst,
	    mb->tail - mb->frst, size, hdr->size);
	return ((void *) hdr) - hdr->size; 
}

int
mm_system_init(size_t rsvd_size)
{
	mb_rsvd_size = rsvd_size + sizeof (struct ele_hdr);
	INIT_LIST_HEAD(&inuse_list);
	INIT_LIST_HEAD(&unuse_list);
	INIT_LIST_HEAD(&touse_list);
	return 0;
}

void
mm_system_exit()
{
}

#ifdef TEST
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static struct list_head list;

struct hhh {
	struct list_head ent;
	size_t size;
	mm_blk_t *mb;
};

void *test(void *arg)
{
	mm_blk_t *mb;
	void *p;
	int total;
	int i;
	struct hhh *hdr;

	while (1) {
		total = 0;
		mb = mm_reserve();
		for (i = 0; i < 10; i++) {
			size_t len = 16 + random() % 20;
		    	p = mm_alloc(mb, len);
			total += len;
		}
		mm_unreserve(mb);

		hdr = p;
		pthread_mutex_lock(&lock);
		list_add(&hdr->ent, &list);
		hdr->size = total;
		hdr->mb = mb;
		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&lock);
	}
}

void *test1(void *arg)
{
	struct hhh *ent;
	pthread_mutex_lock(&lock);
	while (1) {
		while (list_empty(&list)) {
			pthread_cond_wait(&cond, &lock);
		}
		ent = list_first_entry(&list, struct hhh, ent);
		list_del(&ent->ent);
		pthread_mutex_unlock(&lock);
		mm_free(ent->mb, ent, ent->size);
		pthread_mutex_lock(&lock);
	}
	pthread_mutex_unlock(&lock);
}

int main()
{
	pthread_t t;
	int i;

	INIT_LIST_HEAD(&list);

	mm_system_init(400);

    	pthread_create(&t, NULL, test, NULL);
    	pthread_create(&t, NULL, test, NULL);
    	pthread_create(&t, NULL, test1, NULL);
	pthread_join(t, NULL);

}
#endif
