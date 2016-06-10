#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "urandom.h"

int urandom_fd = -2;

int urandom_init()
{
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if(urandom_fd == -1){
        urandom_fd = -2;
        return -1;
    }

    return 0;
}

void urandom_end()
{
    if (urandom_fd != -2)
        close(urandom_fd);
    urandom_fd = -2;
}

unsigned long urandom()
{
    unsigned long buf_impl;
    unsigned long *buf = &buf_impl;
    if(urandom_fd == -2){
        if (urandom_init() == -1)
            return -1;
    }
    /* Read 4 bytes, or 32 bits into *buf, which points to buf_impl */
    read(urandom_fd, buf, sizeof(long));

    urandom_end();
    return buf_impl;
}


