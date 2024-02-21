// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <kernel/semihosting.h>
#include <string.h>

/*
 * ARM and RISC-V have defined the standard way to perform
 * the semihosting operations.
 * - Operation codes and open modes are identical.
 * - The implementation of the low-level __do_semihosting() call is
 *   architecture-specific.
 * - Arm semihosting interface:
 *   https://developer.arm.com/documentation/dui0471/g/Semihosting/The-semihosting-interface
 * - RISC-V semihosting interface:
 *   https://github.com/riscv-non-isa/riscv-semihosting/blob/main/binary-interface.adoc
 */

/* An integer that specifies the file open mode */
enum semihosting_open_mode {
	SEMIHOSTING_OPEN_R = 0,
	SEMIHOSTING_OPEN_RB = 1,
	SEMIHOSTING_OPEN_RX = 2,
	SEMIHOSTING_OPEN_RXB = 3,
	SEMIHOSTING_OPEN_W = 4,
	SEMIHOSTING_OPEN_WB = 5,
	SEMIHOSTING_OPEN_WX = 6,
	SEMIHOSTING_OPEN_WXB = 7,
	SEMIHOSTING_OPEN_A = 8,
	SEMIHOSTING_OPEN_AB = 9,
	SEMIHOSTING_OPEN_AX = 10,
	SEMIHOSTING_OPEN_AXB = 11,
};

#if defined(O_BINARY)
#define SEMIHOSTING_O_BINARY_MODE_OFFSET 1 /* binary mode */
#endif

enum semihosting_sys_ops {
	// Regular operations
	SEMIHOSTING_SYS_OPEN = 0x01,
	SEMIHOSTING_SYS_CLOSE = 0x02,
	SEMIHOSTING_SYS_WRITEC = 0x03,
	SEMIHOSTING_SYS_WRITE = 0x05,
	SEMIHOSTING_SYS_READ = 0x06,
	SEMIHOSTING_SYS_READC = 0x07,
};

struct semihosting_param_t {
	uintptr_t param0;
	uintptr_t param1;
	uintptr_t param2;
};

char semihosting_readc(void)
{
	return __do_semihosting(SEMIHOSTING_SYS_READC, 0);
}

void semihosting_writec(char c)
{
	__do_semihosting(SEMIHOSTING_SYS_WRITEC, (uintptr_t)&c);
}

int semihosting_open(const char *fname, int flags)
{
	int semi_open_flags = 0;
	const int flags_mask = O_RDONLY | O_WRONLY | O_RDWR |
			       O_CREAT | O_TRUNC | O_APPEND;
	struct semihosting_param_t arg = {0};

	/* Convert the flags to semihosting open. */
	switch (flags & flags_mask) {
	case O_RDONLY:				/* 'r' */
		semi_open_flags = SEMIHOSTING_OPEN_R;
		break;
	case O_WRONLY | O_CREAT | O_TRUNC:	/* 'w' */
		semi_open_flags = SEMIHOSTING_OPEN_W;
		break;
	case O_WRONLY | O_CREAT | O_APPEND:	/* 'a' */
		semi_open_flags = SEMIHOSTING_OPEN_A;
		break;
	case O_RDWR:				/* 'r+' */
		semi_open_flags = SEMIHOSTING_OPEN_RX;
		break;
	case O_RDWR | O_CREAT | O_TRUNC:	/* 'w+' */
		semi_open_flags = SEMIHOSTING_OPEN_WX;
		break;
	case O_RDWR | O_CREAT | O_APPEND:	/* 'a+' */
		semi_open_flags = SEMIHOSTING_OPEN_AX;
		break;
	default:
		return -1;
	}

#if defined(O_BINARY)
	if (flags & O_BINARY)
		semi_open_flags += SEMIHOSTING_O_BINARY_MODE_OFFSET; /* 'b' */
#endif

	arg.param0 = (uintptr_t)fname;
	arg.param1 = (uintptr_t)semi_open_flags;
	arg.param2 = (uintptr_t)strlen(fname);

	return __do_semihosting(SEMIHOSTING_SYS_OPEN, (uintptr_t)&arg);
}

ssize_t semihosting_read(int fd, void *ptr, size_t len)
{
	struct semihosting_param_t arg = {
		.param0 = (uintptr_t)fd,
		.param1 = (uintptr_t)ptr,
		.param2 = (uintptr_t)len
	};

	return __do_semihosting(SEMIHOSTING_SYS_READ, (uintptr_t)&arg);
}

ssize_t semihosting_write(int fd, const void *ptr, size_t len)
{
	struct semihosting_param_t arg = {
		.param0 = (uintptr_t)fd,
		.param1 = (uintptr_t)ptr,
		.param2 = (uintptr_t)len
	};

	return __do_semihosting(SEMIHOSTING_SYS_WRITE, (uintptr_t)&arg);
}

int semihosting_close(int fd)
{
	struct semihosting_param_t arg = {
		.param0 = (uintptr_t)fd,
		.param1 = 0,
		.param2 = 0
	};

	return __do_semihosting(SEMIHOSTING_SYS_CLOSE, (uintptr_t)&arg);
}
