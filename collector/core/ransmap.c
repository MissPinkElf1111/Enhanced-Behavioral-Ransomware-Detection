/*
 * Beyond RanSMAP — in-VMM access-pattern collector (core).
 *
 * Phase 3: storage (AHCI/SATA) capture + integer Shannon entropy + a
 * lock-protected record ring + a register-return stat VMCALL for
 * verification.  Memory (EPT) capture, the 30 s re-arm, VMCALL start/stop
 * and the guest B1 drain are added in later phases.
 *
 * The VMM has no FPU, so entropy is computed in Q16 fixed point and carried
 * out as an integer; the guest/offline formatter divides by 65536 to produce
 * the RanSMAP 0..1 float.
 */

#include <core.h>
#include <core/spinlock.h>
#include <core/time.h>
#include <ransmap.h>

/* ---- record ring ---------------------------------------------------- */

/* Power of two.  Sized to absorb the burst of faults right after a 30 s EPT
 * re-arm without the producer (capture) overrunning the consumer (B1 drain):
 * 262144 * 32 B = 8 MiB.  With monitoring gated to the measurement window and
 * the ring reset on start, this keeps in-window `dropped` at zero. */
#define RANSMAP_RING_CAP 262144

static struct ransmap_rec ring[RANSMAP_RING_CAP];
static u32 ring_head;			/* next write index */
static u32 ring_tail;			/* next undrained index (for B1) */
static u64 ring_total;			/* lifetime record count */
static u64 ring_dropped;		/* overwritten-before-drain count */
static u64 cnt_kind[6];			/* per-kind lifetime counts */
static spinlock_t ring_lock = SPINLOCK_INITIALIZER;

/* Snapshot of the most recent storage write, for eyeball verification. */
static u64 last_w_lba;
static u32 last_w_size;
static i32 last_w_ent;

/* Snapshot of the most recent memory write/read-write, for verification. */
static u64 last_m_gpa;
static i32 last_m_ent;
static u8  last_m_type;

/* Diagnostics: how many AHCI/RAID controllers BitVisor attached to, and how
 * many AHCI commands we saw intercepted at the prehook (any command type).
 * Together with the r/w event count these localize a "0 events" failure:
 *   attach=0            -> controller not bound (BIOS SATA mode / VMD)
 *   attach>0, cmds=0    -> bound but command issue not intercepted
 *   attach>0, cmds>0, events=0 -> commands seen but none were r/w */
static u64 dbg_storage_attach;
static u64 dbg_ahci_cmd;

/* Monitoring is OFF by default and switched on via the "ransmap_ctl" VMCALL
 * only around a measurement window (as in RanSMAP).  Capturing during
 * BitVisor/Windows boot would fault in the entire working set at once and
 * stall the machine, so we never capture until the guest explicitly starts. */
/* Storage monitoring is OFF at boot too (it was ON during bring-up for easy
 * verification).  Gating it to the measurement window — armed by ransmap_ctl
 * start, which also resets the ring — means boot/idle I/O never fills and wraps
 * the ring before draining begins, so in-window loss starts from a clean zero. */
static bool monitoring = false;

/* Memory (EPT) monitoring: OFF at boot.  Capturing memory means periodically
 * invalidating EPT to force re-faults, which during boot would fault in the
 * whole working set and stall.  Armed via ransmap_ctl start once the OS is up. */
static bool mem_monitoring = false;

bool
ransmap_enabled (void)
{
	return monitoring;
}

void
ransmap_set_monitoring (bool on)
{
	monitoring = on;
}

bool
ransmap_mem_enabled (void)
{
	return mem_monitoring;
}

void
ransmap_set_mem_monitoring (bool on)
{
	mem_monitoring = on;
}

/* Clear all counters and the ring (called on reset / before a fresh run). */
void
ransmap_reset (void)
{
	int i;

	mem_monitoring = false;
	spinlock_lock (&ring_lock);
	ring_head = ring_tail = 0;
	ring_total = ring_dropped = 0;
	for (i = 0; i < 6; i++)
		cnt_kind[i] = 0;
	last_w_lba = 0;
	last_w_size = 0;
	last_w_ent = 0;
	last_m_gpa = 0;
	last_m_ent = 0;
	last_m_type = 0;
	spinlock_unlock (&ring_lock);
}

void
ransmap_note_storage_attach (void)
{
	dbg_storage_attach++;
}

void
ransmap_note_ahci_cmd (void)
{
	dbg_ahci_cmd++;
}

/* B1 drain: dequeue the oldest undrained record into *out.  Returns false
 * when the ring is empty.  The guest helper calls this in a loop (one record
 * per VMCALL) and formats the RanSMAP CSVs; draining before the ring wraps is
 * what keeps `dropped` at zero. */
bool
ransmap_drain_one (struct ransmap_rec *out)
{
	bool got = false;

	spinlock_lock (&ring_lock);
	if (ring_tail != ring_head) {
		*out = ring[ring_tail];
		ring_tail = (ring_tail + 1) & (RANSMAP_RING_CAP - 1);
		got = true;
	}
	spinlock_unlock (&ring_lock);
	return got;
}

static void
ring_push (const struct ransmap_rec *r)
{
	spinlock_lock (&ring_lock);
	ring[ring_head] = *r;
	ring_head = (ring_head + 1) & (RANSMAP_RING_CAP - 1);
	if (ring_head == ring_tail) {	/* overran undrained data */
		ring_tail = (ring_tail + 1) & (RANSMAP_RING_CAP - 1);
		ring_dropped++;
	}
	ring_total++;
	if (r->kind < 6)
		cnt_kind[r->kind]++;
	spinlock_unlock (&ring_lock);
}

/* ---- Shannon entropy (integer, Q16) --------------------------------- */

/* log2(x) in Q16 fixed point, x >= 1.  Returns 0 for x == 0. */
static u64
log2_q16 (u32 x)
{
	int b;
	u64 y, result;
	int i;

	if (x == 0)
		return 0;
	for (b = 0; (x >> b) > 1; b++)
		;			/* b = floor(log2(x)) */
	result = (u64)b << 16;
	/* y = x / 2^b in Q16, so y is in [1,2) => [0x10000, 0x20000). */
	y = ((u64)x << 16) >> b;
	for (i = 0; i < 16; i++) {
		y = (y * y) >> 16;	/* square, stays Q16 */
		if (y >= (2ULL << 16)) {
			y >>= 1;
			result |= (1ULL << (15 - i));
		}
	}
	return result;
}

/* H = -sum p_i log2 p_i  = log2(N) - (1/N) sum c_i log2(c_i), over bytes.
 * Returned normalized to [0,1] (divide by 8 bits) as Q16. */
i32
ransmap_entropy_q16 (const u8 *buf, u32 len)
{
	u32 hist[256];
	u64 sum_clogc;		/* sum c_i * log2(c_i), Q16 */
	u64 h_q16;
	u32 i;

	if (!buf || len == 0)
		return 0;
	for (i = 0; i < 256; i++)
		hist[i] = 0;
	for (i = 0; i < len; i++)
		hist[buf[i]]++;
	sum_clogc = 0;
	for (i = 0; i < 256; i++)
		if (hist[i])
			sum_clogc += (u64)hist[i] * log2_q16 (hist[i]);
	/* H = log2(len) - sum_clogc/len   (all Q16) */
	h_q16 = log2_q16 (len) - sum_clogc / len;
	h_q16 >>= 3;		/* normalize by 8 bits -> [0,1] */
	if (h_q16 > RANSMAP_ENT_ONE)
		h_q16 = RANSMAP_ENT_ONE;
	return (i32)h_q16;
}

/* ---- storage hook --------------------------------------------------- */

void
ransmap_storage_event (int rw, u64 lba, u32 size_bytes, int sector_size,
		       const u8 *data)
{
	struct ransmap_rec r;
	u64 t_us;

	if (!monitoring)
		return;

	t_us = get_time ();
	if (rw != 1) {		/* STORAGE_READ: one record per command */
		r.t_us = t_us;
		r.addr = lba;
		r.size = size_bytes;
		r.type = RANSMAP_PT_NONE;
		r.kind = RANSMAP_ATA_READ;
		r.ent_q16 = RANSMAP_ENT_NA;
		ring_push (&r);
		return;
	}

	/* STORAGE_WRITE: emit one record per 4096-byte sector so each row's
	 * entropy is a per-sector value (matching RanSAP), not a single value
	 * averaged over a whole multi-sector transfer. */
	u32 off;

	for (off = 0; off < size_bytes; off += 4096) {
		u32 chunk = size_bytes - off;

		if (chunk > 4096)
			chunk = 4096;
		r.t_us = t_us;
		r.addr = sector_size > 0 ? lba + off / sector_size : lba;
		r.size = chunk;
		r.type = RANSMAP_PT_NONE;
		r.kind = RANSMAP_ATA_WRITE;
		r.ent_q16 = ransmap_entropy_q16 (data ? data + off : NULL,
						 chunk);
		last_w_lba = r.addr;
		last_w_size = chunk;
		last_w_ent = r.ent_q16;
		ring_push (&r);
	}
}

/* ---- memory hook ---------------------------------------------------- */

void
ransmap_mem_event (u8 kind, u64 gpa, u32 size, i32 ent_q16, u8 type)
{
	struct ransmap_rec r;

	if (!monitoring)
		return;

	r.t_us = get_time ();
	r.addr = gpa;
	r.size = size;
	r.ent_q16 = ent_q16;
	r.kind = kind;
	r.type = type;
	/* Snapshot only real RAM writes (entropy computed), so the "last mem
	 * write" seen by the stat VMCALL is never an MMIO register access. */
	if ((kind == RANSMAP_MEM_WRITE || kind == RANSMAP_MEM_READWRITE) &&
	    ent_q16 != RANSMAP_ENT_NA) {
		last_m_gpa = gpa;
		last_m_ent = ent_q16;
		last_m_type = type;
	}
	ring_push (&r);
}

/* ---- verification stat (register-return VMCALL backend) ------------- *
 * sel selects a triple of u64 counters returned in the guest's RAX/RBX/RCX.
 * This is a pure-register channel (no guest buffer / kernel driver needed). */
void
ransmap_stat (u32 sel, u64 *a, u64 *b, u64 *c)
{
	spinlock_lock (&ring_lock);
	switch (sel) {
	case 0:		/* totals */
		*a = ring_total;
		*b = cnt_kind[RANSMAP_ATA_WRITE];
		*c = cnt_kind[RANSMAP_ATA_READ];
		break;
	case 1:		/* ring health + last write */
		*a = ring_dropped;
		*b = last_w_lba;
		*c = ((u64)last_w_size << 32) | (u32)last_w_ent;
		break;
	case 2:		/* diagnostics */
		*a = dbg_storage_attach;	/* AHCI/RAID controllers bound */
		*b = cnt_kind[RANSMAP_ATA_WRITE] + cnt_kind[RANSMAP_ATA_READ];
		*c = dbg_ahci_cmd;		/* AHCI commands seen at prehook */
		break;
	case 3:		/* memory counts */
		*a = cnt_kind[RANSMAP_MEM_READ];
		*b = cnt_kind[RANSMAP_MEM_WRITE];
		*c = cnt_kind[RANSMAP_MEM_READWRITE];
		break;
	case 4:		/* memory exec count + last mem write */
		*a = cnt_kind[RANSMAP_MEM_EXEC];
		*b = last_m_gpa;
		*c = ((u64)last_m_type << 32) | (u32)last_m_ent;
		break;
	case 5:		/* monitoring state */
		*a = monitoring ? 1 : 0;
		*b = 0;
		*c = 0;
		break;
	default:
		*a = *b = *c = 0;
		break;
	}
	spinlock_unlock (&ring_lock);
}
