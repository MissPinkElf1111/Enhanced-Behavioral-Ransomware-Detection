# RanSMAP Collector (BitVisor) — environment, build, run

This tree is **matsu/bitvisor @ `a6a2c2a`** plus a storage+memory access-pattern collector. This document covers the environment it was adapted to and how to build, deploy, and run it. Upstream BitVisor's license is in `LICENSE`.

> Note: vendored crypto test fixtures (OpenSSL/mbedTLS demo & test private keys, `.pem` / `.key`) are removed from this copy — they are unused by the build and trip GitHub secret scanning.

## 1. Target environment

Built and tested on the collection host:

- **CPU / RAM:** Intel Core i5‑8265U (Whiskey Lake), 8 GB
- **Monitored disk:** SATA SSD on the Intel AHCI controller, running **Windows 10 Enterprise LTSC 2019**, UEFI / GPT / NTFS
- **Boot:** UEFI from a USB stick (BitVisor), which then boots Windows 10 from the SATA SSD

Environment-specific points baked into this build:

- **Storage capture is AHCI/SATA only**, enabled by `config.vmm.driver.ata = 1` (set in `defconfig.tmpl`). Non‑SATA disks (e.g. an NVMe drive in the same   machine) are **not** monitored.
- **AHCI DMA shadow raised from 4 MiB to 16 MiB per command**
  (`drivers/ata/ahci.c`). Windows 10 on this SATA SSD issues single transfers larger than 4 MiB; the stock 4 MiB limit hits an `ASSERT` and hangs at boot, so the shadow buffer is split into ≤4 MiB PRD entries up to 16 MiB.
- **Memory capture** uses EPT with a **30 s per‑core re‑arm**; both storage and memory monitoring are **OFF at boot** and are armed from the guest.

## 2. What changed vs the base commit

Modified: `drivers/ata/ahci.c` (16 MiB shadow + storage read/write hooks), `core/x86/vt_main.c` (EPT memory capture, 30 s re‑arm, RAM‑vs‑MMIO check, first‑non‑zero‑4KiB entropy), `core/x86/vt_ept.c` + `vt_ept.h` (page‑level helper), `core/x86/vmmcall.c` (VMCALL args/returns extended to RDX/RSI/RDI), `core/Makefile`, `defconfig.tmpl` (`ata = 1`).

Added: `core/ransmap.c` + `include/ransmap.h` (record ring, integer Shannon entropy, counters, drain), `core/vmmcall_ransmap.c` (VMCALLs `ransmap_ctl` / `ransmap_stat` / `ransmap_drain` / `ransmap_now`), `tools/ransmap/ransmapstat.c` + `Makefile` (guest control + CSV tool).

Compile‑time tunables: re‑arm period and per‑cpu table in `core/x86/vt_main.c` (`RANSMAP_REARM_US`), ring size in `core/ransmap.c` (`RANSMAP_RING_CAP`), transfer cap in `drivers/ata/ahci.c` (16 MiB).

## 3. Build

Produces `bitvisor.elf` (hypervisor), `boot/uefi-loader/loadvmm.efi` (UEFI loader), and `tools/ransmap/ransmapstat.exe` (Windows guest tool). Build config is `defconfig`, generated from `defconfig.tmpl` (which sets `ata = 1`); if you edit `defconfig.tmpl`, delete `defconfig` and rebuild.

### Toolchain

A Linux **x86_64** toolchain is required:

- `gcc`, `binutils`, `make`, `bc` — `bitvisor.elf`
- `clang`, `lld` — `boot/uefi-loader/loadvmm.efi`
- `python3` — Kconfig
- `x86_64-w64-mingw32-gcc` (mingw‑w64) — `tools/ransmap/ransmapstat.exe`

On Debian/Ubuntu:
```sh
sudo apt-get install build-essential binutils clang lld python3 bc make \
                     gcc-mingw-w64-x86-64
```

### Commands
```sh
make                                      # -> bitvisor.elf
make -C boot/uefi-loader                  # -> boot/uefi-loader/loadvmm.efi
make -C tools/ransmap X64=1 ransmapstat.exe
```

> The author builds this on macOS (Apple Silicon) inside a Linux/x86_64 Docker container carrying the toolchain above, on a **case‑sensitive** volume — BitVisor has filenames that differ only in case, which a case‑insensitive filesystem cannot check out.

## 4. Deploy (USB, UEFI)

The USB stick boots BitVisor, which then boots Windows 10 from the SATA SSD. Its layout (as seen from Windows, drive `E:`):

```
E:\bitvisor\loadvmm.efi      UEFI loader (started from the UEFI shell)
E:\bitvisor\bitvisor.elf     the hypervisor (loaded by loadvmm.efi)
E:\bitvisor\ransmapstat.exe  guest tool (run later from inside Windows)
E:\EFI\                      UEFI boot files
```

Boot sequence:

1. Power on and boot the laptop from the USB stick (UEFI). It lands in the UEFI shell.
2. Select the USB filesystem and start the loader:
   ```
   fs3:
   bitvisor\loadvmm.efi
   ```
   The USB maps as `fs3:` on this host; on another machine the number may differ — run `map` in the shell to find the USB volume.
3. `loadvmm.efi` loads `bitvisor.elf`, then Windows 10 boots from the SATA SSD under BitVisor.

To deploy a new build, replace `E:\bitvisor\bitvisor.elf` (and `E:\bitvisor\ransmapstat.exe`) on the stick and reboot.

## 5. Run and collect

### Decoy files

The file‑operating benign workloads act on a set of *decoy files* placed on the test machine's Windows 10 Desktop — Zip compresses them — which is what produces the captured storage write activity for those runs. (Idle, Firefox and Office don't touch the decoy files.)
RanSMAP used the first 50 directories (`000`–`049`) of the GovDocs1 corpus (49,321 files, 26.4 GB of PDF / JPEG / HTML / Office); any sufficiently large, varied document set works. The SSD is restored to its original image between runs.

### Collecting

After Windows 10 is up, run the tool **from the USB drive** (e.g. `E:`) so the CSV files land on the USB, not on the monitored SATA disk (writing them to SATA would feed back into the capture):

```
ransmapstat.exe start          # arm monitoring (resets the ring; OFF at boot)
ransmapstat.exe collect 180    # drain to 6 CSVs in the current dir for 180 s
ransmapstat.exe stop           # stop monitoring
ransmapstat.exe                # (no args) print counters + diagnostics
```

- `start` begins storage capture and the 30 s memory re‑arm, and clears the ring so each window starts clean.
- `collect <seconds>` drains records to the 6 CSVs continuously, then prints `wrote N records` and `dropped during window = 0 (lossless)`.
- Use 180 s (3 min) per run; use a shorter value only to verify the pipeline.

## 6. Output — 6 CSV files per run

Each run produces six headerless CSV files; one access per line.

### Storage access files — `ata_read.csv`, `ata_write.csv`

- UNIX Timestamp in seconds, t_s [s]
- UNIX Timestamp in nanoseconds, t_ns [ns]
- Logical Block Address of an accessed sector, LBA
- Size of an accessed sector in bytes, size [byte]
- Normalized Shannon entropy of a written sector, entropy (-1 for reads)

### Memory access files — `mem_read.csv`, `mem_write.csv`, `mem_readwrite.csv`, `mem_exec.csv`

- UNIX Timestamp in seconds, t_s [s]
- UNIX Timestamp in nanoseconds, t_ns [ns]
- Guest Physical Address of an accessed page, GPA
- Size of the sampled page contents in bytes, size [byte]
- Normalized Shannon entropy of written page contents, entropy (-1 for read, execute, and MMIO)
- Memory page type, type (1: 4 KiB, 2: 2 MiB, 3: 1 GiB, 4: MMIO)

### Notes

- t_s / t_ns are wall-clock UNIX time; relative time is the value minus the first timestamp of a run.
- entropy is normalized to a 0 to 1 range; -1 means not applicable (non-write accesses and MMIO).
- Read rows are one per I/O command; write rows are one per 4096-byte sector.
- MMIO memory accesses (type 4) have size 0 and entropy -1.
