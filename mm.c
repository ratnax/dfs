#include<stdio.h>
#include "global.h"
#include "list.h"
#include "mm_ext.h"
//#include "global.h"

#define MEM_BLK_SHFT 16
#define MEM_BLK_SIZE (1 << MEM_BLK_SHFT)

typedef enum {INUSE, UNUSABLE, TOUSE} mb_state_t;

struct ele_hdr {
	uint32_t free:1;
	uint32_t size:31;
};


struct mem_blk {
	mb_state_t	state;
	void		*head;
	void		*tail;
	void		*last;
	struct list_head list;
	char		frst[0];
};

static struct list_head inuse_list;
static struct list_head unuse_list;
static struct list_head touse_list;
static size_t mb_rsvd_size;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static bool __isfull(mm_blk_t *mb)
{
	if (mb->head < mb->tail) {
		return  (mb->head - (void *) mb->frst < mb_rsvd_size && 
			(mb->last - mb->tail < mb_rsvd_size));
	} else { 
		return  (mb->head - mb->tail < mb_rsvd_size);
	}
}

void mm_unreserve(mm_blk_t *mb)
{
	struct ele_hdr *hdr = mb->head;

	assert(mb->state == INUSE);

	mb->head -= hdr->size;
	assert(mb->head >= (void *) (mb + 1));

	pthread_mutex_lock(&mutex);
	list_del(&mb->list);
	if (__isfull(mb)) 
		list_add(&mb->list, &unuse_list);
	else
		list_add(&mb->list, &touse_list);
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

			new_mb->last = ((void *) new_mb) + MEM_BLK_SIZE;
			new_mb->tail = new_mb->last;
			new_mb->head = new_mb->last - sizeof(struct ele_hdr);
			hdr = new_mb->head;
			hdr->free = 0;
			hdr->size = sizeof(struct ele_hdr);
			return new_mb;
		}
	} 

	mb = list_first_entry(&touse_list, struct mem_blk, list);
	list_del(&mb->list);
	list_add(&mb->list, &inuse_list);
	mb->state = INUSE;
	pthread_mutex_unlock(&mutex);
	if (mb->head - (void *) mb->frst < mb_rsvd_size) {
		hdr = mb->head = mb->last - sizeof (struct ele_hdr);
	} else {
		hdr = mb->head = mb->head - sizeof (struct ele_hdr); 
	}
	hdr->free = 0;
	hdr->size = sizeof (struct ele_hdr);
	if (new_mb)
		free(new_mb);
	return mb;
}

void mm_free(mm_blk_t *mb, void *p, size_t size)
{
	struct ele_hdr *hdr = p + size;

	hdr->free = 1;
	pthread_mutex_lock(&mutex);
	hdr = mb->tail - sizeof (struct ele_hdr);
	while (hdr->free == 1) {
		mb->tail -= hdr->size;
		if (mb->tail - (void *) mb->frst < mb_rsvd_size)
			mb->tail = mb->last;
		hdr = mb->tail - sizeof(struct ele_hdr);
	}
	if (mb->state == UNUSABLE && !__isfull(mb)) {
		list_del(&mb->list);
		list_add(&mb->list, &touse_list);
	}
	pthread_mutex_unlock(&mutex);
}

void *mm_alloc(mm_blk_t *mb, size_t size)
{
	struct ele_hdr *hdr = mb->head;

	assert(mb->state == INUSE);
	hdr->size += size;
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

void *test(void *arg)
{
	mm_blk_t *mb;
	char *p[10], *q[100];
	int total = 0, t[100];
	int i, j = 0;

	for (j = 0; j < 100; j++)
		t[j] = 0;

	j = 0;
	while (1) {
		mb = mm_reserve();
	
		for (i = 0; i < 10; i++) {
			size_t len = random() % 20;
		    	p[i] = mm_alloc(mb, len);
			t[j] += len;
		}
		mm_unreserve(mb);
		q[j++] = p[9];
		if (j == 100) {
			for (j=j-1; j >=  0; j--)
				    mm_free(mb, q[j], t[j]); 
			for (j = 0; j < 100; j++)
				t[j] = 0;
			j = 0;
		}
	}
}

int main()
{
	pthread_t t;
	int i;

	mm_system_init(200);
	for (i = 0; i < 10; i++)
	    	pthread_create(&t, NULL, test, NULL);

	pthread_join(t, NULL);

}
