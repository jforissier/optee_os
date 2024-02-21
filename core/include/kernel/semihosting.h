/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */
#ifndef __KERNEL_SEMIHOSTING_H
#define __KERNEL_SEMIHOSTING_H

#include <util.h>

#include <sys/fcntl.h>
#include <sys/types.h>

/* Perform architecture-specific semihosting instructions. */
uintptr_t __do_semihosting(uintptr_t op, uintptr_t arg);

/* Read one character from the semihosting host. */
char semihosting_readc(void);

/* Write one character to the semihosting host. */
void semihosting_writec(char c);

/* Request the semihosting host to open a file on the host system. */
int semihosting_open(const char *fname, int flags);

/* Request the semihosting host to read data from a file on the host system. */
ssize_t semihosting_read(int fd, void *ptr, size_t len);

/* Request the semihosting host to write data into a file on the host system. */
ssize_t semihosting_write(int fd, const void *ptr, size_t len);

/*
 * Request the semihosting host to close a file, which has been opened by
 * semihosting_open(), on the host system.
 */
int semihosting_close(int fd);

#endif /* __KERNEL_SEMIHOSTING_H */
