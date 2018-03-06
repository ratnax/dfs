#ifndef _LIST_H_
#define _LIST_H_
#include<pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <assert.h>

struct list_head {
	struct list_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

#define kfree(x) free(x)
#define kmalloc(x, y) malloc(x)
#define kzalloc(x, y) calloc(1, x)
#define krealloc(x,y,z) realloc(x,y)
#define filp_close(x, y) close(x)
#define mutex_init(x) pthread_mutex_init(x, NULL)
#define mutex_lock(x) pthread_mutex_lock(x)
#define mutex_unlock(x) pthread_mutex_unlock(x)
#define kernel_read(a, b, c, d) pread(a, c, d, b)
#define kernel_write(a, b, c, d) pwrite(a, b, c, d)
#define vfs_fsync(x, y) fsync(x)
#define BUG() assert(0)
#define BUG_ON(x) assert(!(x))

#define KERN_ERR 
#define KERN_WARN
#define KERN_CRIT
#define KERN_INFO

#define printk(x, args...) fprintf(stderr, "%s %d\n",__FILE__, __LINE__ ) 

#define LIST_POISON1  ((void *) 0x100 + 0)
#define LIST_POISON2  ((void *) 0x200 + 0)

static inline void INIT_HLIST_NODE(struct hlist_node *h)
{
	h->next = NULL;
	h->pprev = NULL;
}

#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)

static inline void __hlist_del(struct hlist_node *n)
{
	struct hlist_node *next = n->next;
	struct hlist_node **pprev = n->pprev;

	*pprev = next;
	if (next)
		next->pprev = pprev;
}

static inline void hlist_del(struct hlist_node *n)
{
	__hlist_del(n);
	n->next = LIST_POISON1;
	n->pprev = LIST_POISON2;
}
static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{
	struct hlist_node *first = h->first;
	n->next = first;
	if (first)
		first->pprev = &n->next;
	h->first = n;
	n->pprev = &h->first;
}

static inline int hlist_empty(const struct hlist_head *h)
{
	    return !(h->first);
}

#define container_of(ptr, type, member) ({			\
	const __typeof__( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)

#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)

#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)

#define hlist_entry_safe(ptr, type, member) \
	({ __typeof__(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})

/**
 * hlist_for_each_entry	- iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the hlist_node within the struct.
 */
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, __typeof__(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, __typeof__(*(pos)), member))

static inline void
INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list->prev = list;
}

static inline void
__list_add(struct list_head *entry, struct list_head *prev,
    struct list_head *next)
{
	next->prev = entry;
	entry->next = next;
	entry->prev = prev;
	prev->next = entry;
}

/**
 * Insert a new element after the given list head. The new element does not
 * need to be initialised as empty list.
 * The list changes from:
 *      head → some element → ...
 * to
 *      head → new element → older element → ...
 *
 * Example:
 * struct foo *newfoo = malloc(...);
 * list_add(&newfoo->entry, &bar->list_of_foos);
 *
 * @param entry The new element to prepend to the list.
 * @param head The existing list.
 */
static inline void
list_add(struct list_head *entry, struct list_head *head)
{
	__list_add(entry, head, head->next);
}

/**
 * Append a new element to the end of the list given with this list head.
 *
 * The list changes from:
 *      head → some element → ... → lastelement
 * to
 *      head → some element → ... → lastelement → new element
 *
 * Example:
 * struct foo *newfoo = malloc(...);
 * list_add_tail(&newfoo->entry, &bar->list_of_foos);
 *
 * @param entry The new element to prepend to the list.
 * @param head The existing list.
 */
static inline void
list_add_tail(struct list_head *entry, struct list_head *head)
{
	__list_add(entry, head->prev, head);
}

static inline void
__list_del(struct list_head *prev, struct list_head *next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * Remove the element from the list it is in. Using this function will reset
 * the pointers to/from this element so it is removed from the list. It does
 * NOT free the element itself or manipulate it otherwise.
 *
 * Using list_del on a pure list head (like in the example at the top of
 * this file) will NOT remove the first element from
 * the list but rather reset the list as empty list.
 *
 * Example:
 * list_del(&foo->entry);
 *
 * @param entry The element to remove.
 */
static inline void
list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline int
list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, __typeof__(*(pos)), member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)


#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, __typeof__(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, __typeof__(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))


#endif
