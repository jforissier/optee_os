/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, EPAM Systems
 */
#ifndef SYMBOLS_H
#define SYMBOLS_H

#include <types_ext.h>

/* This struct is exported only because it is used in syms_data.c */
struct syms_table
{
	/* Symbol offset from syms_base */
	uint32_t offset;
	/* Offset of the symbol name in syms_names array */
	uint16_t name_offset;
	/* Length of the symbol name */
	uint8_t name_len;
	uint8_t pad;
};

int syms_get_name(vaddr_t addr, char *buf, size_t buf_len);
ssize_t syms_get_offset(vaddr_t addr);

#endif  /* SYMBOLS_H */
