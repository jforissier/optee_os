/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */
#ifndef __DRIVERS_SEMIHOSTING_CONSOLE_H
#define __DRIVERS_SEMIHOSTING_CONSOLE_H

#include <drivers/serial.h>

struct semihosting_console_data {
	struct serial_chip chip;
	const char *file_path;
	int fd;
};

/*
 * Initialize console which uses architecture-specific semihosting mechanism.
 * If "file_path" is not NULL, OP-TEE OS will try to output log to that file.
 * Otherwise, if "file_path" is NULL, OP-TEE OS will try to output log to the
 * semihosting console.
 */
void semihosting_console_init(struct semihosting_console_data *pd,
			      const char *file_path);

#endif /* __DRIVERS_SEMIHOSTING_CONSOLE_H */
