#ifndef   MEM_STATS_H
#define   MEM_STATS_H
#include <stdlib.h>
#include <sys/types.h>

#define PERMS_READ               1U
#define PERMS_WRITE              2U
#define PERMS_EXEC               4U
#define PERMS_SHARED             8U
#define PERMS_PRIVATE           16U

typedef struct address_range address_range;
struct address_range {
    struct address_range    *next;
    void                    *start;
    size_t                   length;
    unsigned long            offset;
    dev_t                    device;
    ino_t                    inode;
    unsigned char            perms;
    char                     name[];
};

address_range *mem_stats(pid_t);
void free_mem_stats(address_range *);

#endif /* MEM_STATS_H */
