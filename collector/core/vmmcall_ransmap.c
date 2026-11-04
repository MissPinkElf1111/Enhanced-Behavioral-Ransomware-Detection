/*
 * Beyond RanSMAP — VMCALL interface to the collector.
 *
 * Phase 3: a register-only "ransmap_stat" call for verification.  The guest
 * passes a selector in RBX and reads three u64 counters back in RAX/RBX/RCX.
 * Using registers (not a shared buffer) means a plain user-mode guest tool
 * works with no kernel driver, exactly like dbgsh.
 */

#include <core.h>
#include <core/initfunc.h>
#include <core/time.h>
#include <arch/vmmcall.h>
#include <ransmap.h>
#include "vmmcall.h"

static void
ransmap_stat_call (void)
{
	ulong sel;
	u64 a = 0, b = 0, c = 0;

	vmmcall_arch_read_arg (1, &sel);	/* RBX = selector */
	ransmap_stat ((u32)sel, &a, &b, &c);
	vmmcall_arch_write_arg (0, a);		/* RAX */
	vmmcall_arch_write_arg (1, b);		/* RBX */
	vmmcall_arch_write_arg (2, c);		/* RCX */
}

/* ransmap_ctl: RBX = command (0 stop, 1 start, 2 reset+stop).  Returns the
 * monitoring state (1 on / 0 off) in RAX. */
static void
ransmap_ctl_call (void)
{
	ulong cmd;

	vmmcall_arch_read_arg (1, &cmd);
	switch (cmd) {
	case 0:
		ransmap_set_monitoring (false);
		ransmap_set_mem_monitoring (false);
		break;
	case 1:
		/* Start a clean measurement window: drop anything buffered from
		 * a previous run or the start-to-collect gap, so in-window
		 * `dropped` counts only real loss during THIS window. */
		ransmap_reset ();
		ransmap_set_monitoring (true);
		ransmap_set_mem_monitoring (true);
		break;
	case 2:
		ransmap_set_monitoring (false);
		ransmap_set_mem_monitoring (false);
		ransmap_reset ();
		break;
	}
	vmmcall_arch_write_arg (0, ransmap_enabled () ? 1 : 0);
}

/* ransmap_drain: dequeue one record.  RAX = 1 and the record is returned
 * across RBX/RCX/RDX/RSI/RDI; RAX = 0 means the ring is currently empty.
 *   RAX = got (1/0)
 *   RBX = t_us          (microsecond timestamp)
 *   RCX = addr          (LBA for storage, GPA for memory)
 *   RDX = size          (bytes; 0 for reads/exec)
 *   RSI = ent_q16       (Q16 entropy in [0,0x10000], or 0xFFFFFFFF for -1)
 *   RDI = kind | type<<8 (enum ransmap_kind, enum ransmap_pagetype) */
static void
ransmap_drain_call (void)
{
	struct ransmap_rec r;

	if (!ransmap_drain_one (&r)) {
		vmmcall_arch_write_arg (0, 0);
		return;
	}
	vmmcall_arch_write_arg (0, 1);
	vmmcall_arch_write_arg (1, r.t_us);
	vmmcall_arch_write_arg (2, r.addr);
	vmmcall_arch_write_arg (3, r.size);
	vmmcall_arch_write_arg (4, (u32) r.ent_q16);
	vmmcall_arch_write_arg (5, (u64) r.kind | ((u64) r.type << 8));
}

/* ransmap_now: returns the VMM clock (get_time, microseconds) in RAX.  The
 * guest pairs this once with its own wall clock to convert the per-record
 * boot-relative timestamps into UNIX time for the RanSMAP CSVs. */
static void
ransmap_now_call (void)
{
	vmmcall_arch_write_arg (0, get_time ());
}

static void
vmmcall_ransmap_init (void)
{
	vmmcall_register ("ransmap_stat", ransmap_stat_call);
	vmmcall_register ("ransmap_ctl", ransmap_ctl_call);
	vmmcall_register ("ransmap_drain", ransmap_drain_call);
	vmmcall_register ("ransmap_now", ransmap_now_call);
}

INITFUNC ("vmmcal0", vmmcall_ransmap_init);
