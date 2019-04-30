#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "memstats.h"

#include <sys/sysmacros.h>

void free_mem_stats(address_range *list)
{
    while (list) {
        address_range *curr = list;

        list = list->next;

        curr->next = NULL;
        curr->length = 0;
        curr->perms = 0U;
        curr->name[0] = '\0';

        free(curr);
    }
}

address_range *mem_stats(pid_t pid)
{
    address_range *list = NULL;
    char          *line = NULL;
    size_t         size = 0;
    FILE          *maps;

    if (pid > 0) {
        char namebuf[128];
        int  namelen;

        namelen = snprintf(namebuf, sizeof namebuf, "/proc/%ld/maps", (long)pid);
        if (namelen < 12) {
            errno = EINVAL;
            return NULL;
        }

        maps = fopen(namebuf, "r");
    } else
        maps = fopen("/proc/self/maps", "r");

    if (!maps)
        return NULL;

    while (getline(&line, &size, maps) > 0) {
        address_range *curr;
        char           perms[8];
        unsigned int   devmajor, devminor;
        unsigned long  addr_start, addr_end, offset, inode;
        int            name_start = 0;
        int            name_end = 0;

        if (sscanf(line, "%lx-%lx %7s %lx %u:%u %lu %n%*[^\n]%n",
                         &addr_start, &addr_end, perms, &offset,
                         &devmajor, &devminor, &inode,
                         &name_start, &name_end) < 7) {
            fclose(maps);
            free(line);
            free_mem_stats(list);
            errno = EIO;
            return NULL;
        }

        if (name_end <= name_start)
            name_start = name_end = 0;

        curr = malloc(sizeof (address_range) + (size_t)(name_end - name_start) + 1);
        if (!curr) {
            fclose(maps);
            free(line);
            free_mem_stats(list);
            errno = ENOMEM;
            return NULL;
        }

        if (name_end > name_start)
            memcpy(curr->name, line + name_start, name_end - name_start);
        curr->name[name_end - name_start] = '\0';

        curr->start = (void *)addr_start;
        curr->length = addr_end - addr_start;
        curr->offset = offset;
        curr->device = makedev(devmajor, devminor);
        curr->inode = (ino_t)inode;

        curr->perms = 0U;
        if (strchr(perms, 'r'))
            curr->perms |= PERMS_READ;
        if (strchr(perms, 'w'))
            curr->perms |= PERMS_WRITE;
        if (strchr(perms, 'x'))
            curr->perms |= PERMS_EXEC;
        if (strchr(perms, 's'))
            curr->perms |= PERMS_SHARED;
        if (strchr(perms, 'p'))
            curr->perms |= PERMS_PRIVATE;

        curr->next = list;
        list = curr;
    }

    free(line);

    if (!feof(maps) || ferror(maps)) {
        fclose(maps);
        free_mem_stats(list);
        errno = EIO;
        return NULL;
    }
    if (fclose(maps)) {
        free_mem_stats(list);
        errno = EIO;
        return NULL;
    }

    errno = 0;
    return list;
}
#endif
