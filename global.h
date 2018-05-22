#ifndef __GLOBAL_H__
#define __GLOBAL_H__

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "err.h"

//#define printf(fmt, ...) 
#define eprintf(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

