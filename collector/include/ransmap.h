/*
 * Beyond RanSMAP — in-VMM storage/memory access-pattern collector.
 *
 * Public API shared between the core VMM (core/ransmap.c) and the
 * parapass-through storage lib (storage/lib/storage.c).  Replicates the
 * RanSAP/RanSMAP attribute set; records are buffered in the VMM and later
 * drained to the guest helper (B1) which formats the RanSMAP CSVs.
 */

#ifndef _RANSMAP_H_
#define _RANSMAP_H_

#include <core/types.h>

/* Record kinds — one per RanSMAP CSV file. */
enum ransmap_kind {
	RANSMAP_ATA_READ = 0,	/* ata_read.csv      : entropy = -1        */
	RANSMAP_ATA_WRITE,	/* ata_write.csv     : entropy 0..1        */
	RANSMAP_MEM_READ,	/* mem_read.csv      : size 0, entropy -1  */
	RANSMAP_MEM_WRITE,	/* mem_write.csv     : entropy 0..1        */
	RANSMAP_MEM_READWRITE,	/* mem_readwrite.csv : entropy 0..1        */
	RANSMAP_MEM_EXEC,	/* mem_exec.csv      : size 0, entropy -1  */
};

/* Page type for memory records (RanSMAP "type" enum). 0 for storage. */
enum ransmap_pagetype {
	RANSMAP_PT_NONE = 0,
	RANSMAP_PT_4KIB = 1,
	RANSMAP_PT_2MIB = 2,
	RANSMAP_PT_1GIB = 3,
	RANSMAP_PT_MMIO = 4,
};

/* Entropy is carried as Q16 fixed point normalized to [0,1]:
 * 0x10000 (RANSMAP_ENT_ONE) == 1.0.  RANSMAP_ENT_NA == not applicable (-1). */
#define RANSMAP_ENT_ONE		(1 << 16)
#define RANSMAP_ENT_NA		(-1)

struct ransmap_rec {
	u64	t_us;		/* timestamp, microseconds (get_time) */
	u64	addr;		/* LBA (storage) or GPA (memory) */
	u32	size;		/* bytes transferred (0 for read/exec) */
	i32	ent_q16;	/* Q16 entropy in [0,RANSMAP_ENT_ONE], or RANSMAP_ENT_NA */
	u8	kind;		/* enum ransmap_kind */
	u8	type;		/* enum ransmap_pagetype */
};

/* Shannon entropy of buf[0..len), normalized to [0,1], as Q16 fixed point.
 * len == 0 returns 0.  Integer-only (no FPU in the VMM). */
i32 ransmap_entropy_q16 (const u8 *buf, u32 len);

/* Is storage monitoring currently active?  On from boot in this build. */
bool ransmap_enabled (void);
void ransmap_set_monitoring (bool on);
void ransmap_reset (void);

/* Memory (EPT) monitoring is a SEPARATE gate, OFF at boot: arming it starts
 * the periodic EPT re-arm that surfaces RAM accesses, which would stall the
 * machine during boot.  Armed/disarmed together with storage via ransmap_ctl
 * start/stop (the guest runs it once the OS is up). */
bool ransmap_mem_enabled (void);
void ransmap_set_mem_monitoring (bool on);

/* Diagnostic: called once per AHCI/RAID controller BitVisor attaches to. */
void ransmap_note_storage_attach (void);
void ransmap_note_ahci_cmd (void);

/* Verification/debug counters, returned via the "ransmap_stat" VMCALL.
 * sel picks a triple of u64 values (see core/ransmap.c). */
void ransmap_stat (u32 sel, u64 *a, u64 *b, u64 *c);

/* B1 drain: dequeue the oldest undrained record; false if the ring is empty. */
bool ransmap_drain_one (struct ransmap_rec *out);

/* Storage hook: called from the AHCI driver for every monitored transfer.
 * rw: 0 = read (STORAGE_READ), 1 = write (STORAGE_WRITE).  data points at the
 * transfer buffer (write entropy source; may be NULL).  sector_size lets the
 * write path split the transfer into 4096-byte sectors, emitting one record
 * per sector with that sector's entropy (RanSAP granularity). */
void ransmap_storage_event (int rw, u64 lba, u32 size_bytes, int sector_size,
			    const u8 *data);

/* Memory hook: called from the EPT-violation handler for a classified access.
 * kind is one of the RANSMAP_MEM_* values; size/ent_q16 are 0/-1 for
 * read/exec and MMIO; type is a RANSMAP_PT_* page type. */
void ransmap_mem_event (u8 kind, u64 gpa, u32 size, i32 ent_q16, u8 type);

#endif
