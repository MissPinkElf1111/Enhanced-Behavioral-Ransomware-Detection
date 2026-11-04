/*
 * Beyond RanSMAP — guest-side verification + collection tool.
 *
 * Register-only vmmcalls (no buffer / kernel driver), like dbgsh.
 *   ransmapstat start        -> begin monitoring (storage stays on from boot;
 *                               this also arms the memory/EPT 30 s sampling)
 *   ransmapstat stop         -> stop monitoring (storage + memory)
 *   ransmapstat reset        -> stop + clear all counters and the ring
 *   ransmapstat              -> print the collected counters
 *   ransmapstat collect [s]  -> drain the record ring into the 6 RanSMAP CSVs
 *                               in the current directory, for `s` seconds
 *                               (default: until Ctrl-C).  Run this on a
 *                               NON-SATA volume (e.g. the USB stick) so the
 *                               CSV writes do not feed back into the capture.
 *
 * Build (Windows x64): make -C tools/ransmap X64=1 ransmapstat.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include "../common/call_vmm.h"

/* Must match enum ransmap_kind in the VMM (include/ransmap.h). */
enum {
	K_ATA_READ = 0,
	K_ATA_WRITE,
	K_MEM_READ,
	K_MEM_WRITE,
	K_MEM_READWRITE,
	K_MEM_EXEC,
	K_NUM
};

static volatile int stop_flag;

static void
on_sigint (int sig)
{
	(void)sig;
	stop_flag = 1;
}

static void
sleep_ms (int ms)
{
#ifdef _WIN32
	Sleep (ms);
#else
	usleep (ms * 1000);
#endif
}

/* Call "ransmap_ctl" with command cmd (0 stop, 1 start, 2 reset).
 * Returns monitoring state (1/0), or -1 if the call is unavailable. */
static int
ransmap_ctl (long cmd)
{
	call_vmm_function_t f;
	call_vmm_arg_t arg;
	call_vmm_ret_t ret;

	CALL_VMM_GET_FUNCTION ("ransmap_ctl", &f);
	if (!call_vmm_function_callable (&f))
		return -1;
	arg.rbx = cmd;
	call_vmm_call_function (&f, &arg, &ret);
	return (int)ret.rax;
}

/* Call "ransmap_stat" with selector sel; return the RAX/RBX/RCX triple. */
static int
ransmap_stat (long sel, unsigned long long *a, unsigned long long *b,
	      unsigned long long *c)
{
	call_vmm_function_t f;
	call_vmm_arg_t arg;
	call_vmm_ret_t ret;

	CALL_VMM_GET_FUNCTION ("ransmap_stat", &f);
	if (!call_vmm_function_callable (&f))
		return -1;
	arg.rbx = sel;
	call_vmm_call_function (&f, &arg, &ret);
	*a = (unsigned long long)ret.rax;
	*b = (unsigned long long)ret.rbx;
	*c = (unsigned long long)ret.rcx;
	return 0;
}

/* One drained record. */
struct rec {
	unsigned long long t_us;
	unsigned long long addr;
	unsigned int size;
	int ent_q16;			/* -1 == not applicable */
	unsigned char kind;
	unsigned char type;		/* 0 none, 1 4KiB, 2 2MiB, 3 1GiB, 4 MMIO */
};

/* Drain one record via "ransmap_drain".  Returns 1 if a record was returned,
 * 0 if the ring is empty, -1 if the call is unavailable. */
static int
ransmap_drain (struct rec *r)
{
	/* Resolve the VMCALL number once; the drain loop runs millions of
	 * times, so re-resolving each call would add a wasteful lookup VMCALL
	 * per record. */
	static call_vmm_function_t f;
	static int resolved;
	call_vmm_arg_t arg;
	call_vmm_ret_t ret;

	if (!resolved) {
		CALL_VMM_GET_FUNCTION ("ransmap_drain", &f);
		resolved = 1;
	}
	if (!call_vmm_function_callable (&f))
		return -1;
	memset (&arg, 0, sizeof arg);
	call_vmm_call_function (&f, &arg, &ret);
	if (!ret.rax)
		return 0;
	r->t_us = (unsigned long long)ret.rbx;
	r->addr = (unsigned long long)ret.rcx;
	r->size = (unsigned int)ret.rdx;
	r->ent_q16 = (int)(unsigned int)ret.rsi;	/* 0xFFFFFFFF -> -1 */
	r->kind = (unsigned char)(ret.rdi & 0xFF);
	r->type = (unsigned char)((ret.rdi >> 8) & 0xFF);
	return 1;
}

/* VMM clock (get_time, microseconds) via "ransmap_now"; 0 if unavailable. */
static unsigned long long
ransmap_now_us (void)
{
	call_vmm_function_t f;
	call_vmm_arg_t arg;
	call_vmm_ret_t ret;

	CALL_VMM_GET_FUNCTION ("ransmap_now", &f);
	if (!call_vmm_function_callable (&f))
		return 0;
	memset (&arg, 0, sizeof arg);
	call_vmm_call_function (&f, &arg, &ret);
	return (unsigned long long)ret.rax;
}

/* Current wall-clock time in nanoseconds since the UNIX epoch. */
static unsigned long long
wall_ns (void)
{
#ifdef _WIN32
	FILETIME ft;
	ULARGE_INTEGER u;

	GetSystemTimePreciseAsFileTime (&ft);
	u.LowPart = ft.dwLowDateTime;
	u.HighPart = ft.dwHighDateTime;
	/* FILETIME is 100 ns ticks since 1601-01-01; shift epoch to 1970. */
	return (u.QuadPart - 116444736000000000ULL) * 100ULL;
#else
	struct timespec ts;

	clock_gettime (CLOCK_REALTIME, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ULL +
		(unsigned long long)ts.tv_nsec;
#endif
}

/* Format entropy: -1 for n/a, else q16/65536 as a 0..1 float. */
static void
ent_str (int ent_q16, char *buf, size_t n)
{
	if (ent_q16 < 0)
		snprintf (buf, n, "-1");
	else
		snprintf (buf, n, "%.6f", (double)ent_q16 / 65536.0);
}

static int
do_collect (long seconds)
{
	static const char *names[K_NUM] = {
		"ata_read.csv", "ata_write.csv",
		"mem_read.csv", "mem_write.csv",
		"mem_readwrite.csv", "mem_exec.csv"
	};
	FILE *fp[K_NUM];
	struct rec r;
	char ebuf[32];
	unsigned long long t_s, t_ns, abs_ns;
	unsigned long long written = 0;
	long long offset_ns;
	time_t start_t;
	int i, got;

	/* Probe the drain VMCALL first. */
	if (ransmap_drain (&r) < 0) {
		fprintf (stderr, "vmmcall \"ransmap_drain\" unavailable "
			 "(is this BitVisor build loaded?)\n");
		return 1;
	}

	for (i = 0; i < K_NUM; i++) {
		fp[i] = fopen (names[i], "wb");
		if (!fp[i]) {
			fprintf (stderr, "cannot open %s\n", names[i]);
			while (--i >= 0)
				fclose (fp[i]);
			return 1;
		}
	}

	/* Pair the VMM clock with wall-clock time once so the per-record
	 * boot-relative timestamps convert to UNIX time (as in RanSMAP's CSVs).
	 * Both clocks are monotonic, so one offset applies to every record. */
	offset_ns = (long long)wall_ns () -
		(long long)(ransmap_now_us () * 1000ULL);

	signal (SIGINT, on_sigint);
	start_t = time (NULL);
	printf ("collecting into 6 CSVs%s ... (Ctrl-C to stop)\n",
		seconds > 0 ? " for a fixed time" : "");

	/* NOTE: the record we probed with above was consumed; write it too. */
	got = 1;
	do {
		if (got == 1 && r.kind < K_NUM) {
			abs_ns = (unsigned long long)
				((long long)(r.t_us * 1000ULL) + offset_ns);
			t_s = abs_ns / 1000000000ULL;
			t_ns = abs_ns % 1000000000ULL;
			ent_str (r.ent_q16, ebuf, sizeof ebuf);
			if (r.kind == K_ATA_READ || r.kind == K_ATA_WRITE)
				fprintf (fp[r.kind], "%llu,%llu,%llu,%u,%s\n",
					 t_s, t_ns, r.addr, r.size, ebuf);
			else
				fprintf (fp[r.kind],
					 "%llu,%llu,%llu,%u,%s,%u\n",
					 t_s, t_ns, r.addr, r.size, ebuf,
					 r.type);
			written++;
		} else if (got == 0) {
			sleep_ms (2);	/* ring empty: back off briefly */
		}
		if (stop_flag)
			break;
		if (seconds > 0 && time (NULL) - start_t >= seconds)
			break;
		got = ransmap_drain (&r);
	} while (got >= 0);

	for (i = 0; i < K_NUM; i++)
		fclose (fp[i]);
	printf ("\nwrote %llu records to 6 CSVs.\n", written);
	{
		unsigned long long da, db, dc;

		if (ransmap_stat (1, &da, &db, &dc) == 0)
			printf ("dropped during window = %llu  %s\n", da,
				da ? "(!! WINDOW LOSS — enlarge ring or slow "
				"the workload)" : "(lossless)");
	}
	return 0;
}

int
main (int argc, char **argv)
{
	unsigned long long a, b, c;
	unsigned int last_size;
	int last_ent_q16;

	if (argc > 1 && !strcmp (argv[1], "collect")) {
		long secs = (argc > 2) ? atol (argv[2]) : 0;
		return do_collect (secs);
	}

	if (argc > 1) {
		long cmd = -1;
		if (!strcmp (argv[1], "start"))
			cmd = 1;
		else if (!strcmp (argv[1], "stop"))
			cmd = 0;
		else if (!strcmp (argv[1], "reset"))
			cmd = 2;
		if (cmd < 0) {
			fprintf (stderr, "usage: %s [start|stop|reset|collect "
				 "[seconds]]\n", argv[0]);
			return 2;
		}
		a = ransmap_ctl (cmd);
		if ((int)a < 0) {
			fprintf (stderr, "vmmcall \"ransmap_ctl\" failed "
				 "(is this BitVisor build loaded?)\n");
			return 1;
		}
		printf ("monitoring is now %s\n", a ? "ON" : "OFF");
		return 0;
	}

	if (ransmap_stat (0, &a, &b, &c)) {
		fprintf (stderr, "vmmcall \"ransmap_stat\" failed "
			 "(is this BitVisor build loaded?)\n");
		return 1;
	}
	if (ransmap_stat (5, &a, &b, &c) == 0)
		printf ("monitoring    = %s\n", a ? "ON" : "OFF (run: "
			"ransmapstat start)");
	ransmap_stat (0, &a, &b, &c);
	printf ("records total = %llu\n", a);
	printf ("  ata_write   = %llu\n", b);
	printf ("  ata_read    = %llu\n", c);

	if (ransmap_stat (1, &a, &b, &c) == 0) {
		last_size = (unsigned int)(c >> 32);
		last_ent_q16 = (int)(unsigned int)(c & 0xffffffffu);
		printf ("dropped       = %llu\n", a);
		printf ("last write    : lba=%llu size=%u entropy=", b, last_size);
		if (last_ent_q16 < 0)
			printf ("-1 (n/a)\n");
		else
			printf ("%.4f  (q16=%d)\n",
				(double)last_ent_q16 / 65536.0, last_ent_q16);
	}

	if (ransmap_stat (2, &a, &b, &c) == 0) {
		printf ("--- diagnostics ---\n");
		printf ("AHCI/RAID controllers bound by BitVisor = %llu\n", a);
		printf ("AHCI commands intercepted (any type)    = %llu\n", c);
		printf ("storage r/w events seen                 = %llu\n", b);
		printf ("\n");
		if (a == 0)
			printf ("=> controller NOT bound: SATA is likely in RST/VMD"
				" (not plain AHCI), or no SATA disk present.\n");
		else if (c == 0)
			printf ("=> controller bound but no commands trapped:"
				" guest I/O not reaching the AHCI port.\n");
		else if (b == 0)
			printf ("=> commands seen but none classified r/w"
				" (unexpected — report this).\n");
		else
			printf ("=> capture working.\n");
	}

	if (ransmap_stat (3, &a, &b, &c) == 0) {
		unsigned long long mr = a, mw = b, mrw = c, mx = 0;
		unsigned long long last_gpa = 0;
		int last_ent_q16_m = 0;
		unsigned int last_type = 0;

		if (ransmap_stat (4, &a, &b, &c) == 0) {
			mx = a;
			last_gpa = b;
			last_type = (unsigned int)(c >> 32);
			last_ent_q16_m = (int)(unsigned int)(c & 0xffffffffu);
		}
		printf ("--- memory (EPT) ---\n");
		printf ("mem_read      = %llu\n", mr);
		printf ("mem_write     = %llu\n", mw);
		printf ("mem_readwrite = %llu\n", mrw);
		printf ("mem_exec      = %llu\n", mx);
		if (mw + mrw > 0) {
			printf ("last mem write: gpa=0x%llx type=%u entropy=",
				last_gpa, last_type);
			if (last_ent_q16_m < 0)
				printf ("-1 (n/a)\n");
			else
				printf ("%.4f  (q16=%d)\n",
					(double)last_ent_q16_m / 65536.0,
					last_ent_q16_m);
		}
		if (mr + mw + mrw + mx == 0)
			printf ("=> no memory events (EPT hook not firing?)\n");
		else
			printf ("=> memory capture working.\n");
	}
	return 0;
}
