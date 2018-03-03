#ifndef __ERR_H__
#define __ERR_H__

#define MAX_ERRNO	4096
#define IS_ERR_VALUE(x)	((x) >= (unsigned long)-MAX_ERRNO)

static inline void * ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}
#endif
