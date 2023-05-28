/* SPDX-License-Identifier: GPL-2.0 */
/*
 * riscv.S -- start up code for no-MMU ELF link loader
 *
 * Copyright (C) 2022-2023 Hesham Almatary <hesham.almatary@cl.cam.ac.uk>
 * (C) Copyright 2022, Greg Ungerer <gerg@kernel.org>
 */

.text

.global _start
.global linker

_start:
	cmove	cs1, ca0			/* save the _atexit func for later */
	cmove	ca0, ca1			/* 'mapaddr' for execitable */
	cmove	ca1, ca3			/* 'dynaddr' argument */

	cllc cra, linker
	cjalr cra
	#call	linker			/* relocate it */

	cmove	cra, ca0			/* program entry address */
	cmove	ca0, cs1			/* restore _atexit func ptr */
	cret				/* start the program proper */

