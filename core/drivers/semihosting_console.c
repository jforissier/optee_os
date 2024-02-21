// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <compiler.h>
#include <drivers/semihosting_console.h>
#include <kernel/semihosting.h>
#include <util.h>

static void semihosting_console_putc(struct serial_chip *chip __unused, int ch)
{
	semihosting_writec(ch);
}

static int semihosting_console_getchar(struct serial_chip *chip __unused)
{
	return semihosting_readc();
}

static const struct serial_ops semihosting_console_ops = {
	.putc = semihosting_console_putc,
	.getchar = semihosting_console_getchar,
};
DECLARE_KEEP_PAGER(semihosting_console_ops);

static void semihosting_console_fd_putc(struct serial_chip *chip __unused,
					int ch)
{
	struct semihosting_console_data *pd =
		container_of(chip, struct semihosting_console_data, chip);

	semihosting_write(pd->fd, &ch, 1);
}

static const struct serial_ops semihosting_console_fd_ops = {
	.putc = semihosting_console_fd_putc,
};
DECLARE_KEEP_PAGER(semihosting_console_fd_ops);

void semihosting_console_init(struct semihosting_console_data *pd,
			      const char *file_path)
{
	if (file_path) {
		/* Output log to given file. */
		pd->chip.ops = &semihosting_console_fd_ops;
		pd->file_path = file_path;
		pd->fd = semihosting_open(pd->file_path,
					  O_RDWR | O_CREAT | O_TRUNC);
	} else {
		/* Output log to semihosting console. */
		pd->chip.ops = &semihosting_console_ops;
		pd->file_path = NULL;
		pd->fd = -1;
	}
}
