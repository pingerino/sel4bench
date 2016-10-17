/*
 * Copyright 2016, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(D61_BSD)
 */
#include "../../env.h"

#include <sel4/bootinfo.h>

void
plat_setup(env_t *env)
{
 	if (config_set(CONFIG_X86_64)) {
     	/* check if the cpu supports rdtscp */
    	int edx = 0;
	    asm volatile("cpuid":"=d"(edx):"a"(0x80000001):"ecx");
      	ZF_LOGF_IF((edx & (BIT(27))) == 0, "CPU does not support rdtscp instruction");
 	}

    ZF_LOGI("TSC runs at %u mhz\n", seL4_GetBootInfo()->archInfo);
}
