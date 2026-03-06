# Stacker

A multi-architecture stack tracer for Linux processes that supports both x86_64 and ARM64 architectures.

## Features

- **Multi-architecture support**: Works on both x86_64 and ARM64 (aarch64) Linux systems
- **Thread discovery**: Automatically finds and traces all threads in a target process
- **Register dumping**: Shows architecture-specific CPU registers for each thread
- **Stack unwinding**: Walks the call stack using architecture-appropriate methods
- **Symbol resolution**: Resolves addresses to function names, file names, and line numbers using built-in DWARF parsing
- **Minimal process interruption**: Quickly captures stack traces and detaches to minimize impact
- **Fully static binaries**: Ships as self-contained, statically-linked executables (musl libc) — no runtime dependencies

## Supported Architectures

- **x86_64 (amd64)**: Full support with x86_64-specific register names and stack walking
- **ARM64 (aarch64)**: Full support with ARM64-specific register names and stack walking

## Dependencies

- Linux kernel with ptrace support
- Rust toolchain (stable)

## Building

The project is set up to produce **fully static, musl-linked binaries** via a `Makefile`. The resulting executables have zero shared-library dependencies and can be copied to any Linux machine of the matching architecture.

### One-time setup

Install the required system packages and Rust targets:

```bash
make setup
```

This installs (via `apt-get`):

| Package | Purpose |
|---|---|
| `musl-tools` | Provides `x86_64-linux-musl-gcc` for native static builds |
| `musl-dev` | musl headers and static `libc.a` |
| `clang-19` | Cross-compiler backend used for aarch64 linking |
| `lld-19` | LLVM linker backend used by the aarch64 wrapper |
| `gcc-aarch64-linux-gnu` | Provides the aarch64 sysroot (`crt1.o` etc.) that clang needs |

It also runs:

```bash
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```

### Building

```bash
make          # static binary for the host architecture (default)
make amd64    # static x86_64 binary
make arm64    # static aarch64 binary  (cross-compiled from any host)
make all      # both architectures at once
```

Binaries are placed in the `dist/` directory:

| Target | Output binary |
|---|---|
| x86_64 | `dist/stacker-amd64` |
| aarch64 | `dist/stacker-arm64` |

### Installing

```bash
make install                    # installs to /usr/local/bin/stacker
make install PREFIX=~/.local    # installs to ~/.local/bin/stacker
make install DESTDIR=/tmp/pkg   # staging install (e.g. for packaging)
```

### Verifying static linkage

```bash
make check
```

Runs `ldd` and `file` on every binary under `dist/` and reports whether each one is truly statically linked.

### Cleaning up

```bash
make clean    # removes dist/ and the Cargo build cache
```

---

## How Static Builds Work

Stacker is linked against [musl libc](https://musl.libc.org/) instead of glibc, which allows the linker to produce a single, self-contained binary with zero shared-library dependencies. The binary runs on any Linux system of the matching architecture, regardless of which C library version is installed there.

### Cargo target configuration (`.cargo/config.toml`)

Each musl target is configured with the correct linker and the `+crt-static` target feature so the C runtime is baked into the binary:

```toml
[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"
rustflags = ["-C", "target-feature=+crt-static"]

[target.aarch64-unknown-linux-musl]
linker = "aarch64-linux-musl-gcc"
rustflags = ["-C", "target-feature=+crt-static"]
```

### aarch64 cross-linker wrapper (`scripts/aarch64-linux-musl-gcc`)

Ubuntu does not ship an `aarch64-linux-musl-gcc` binary out of the box, so the repository provides a small shell wrapper at `scripts/aarch64-linux-musl-gcc` that Cargo invokes as the linker for the `aarch64-unknown-linux-musl` target. It delegates to `clang-19` with the right `--target` flag, points at the aarch64 GNU sysroot for the C runtime startup objects, and uses `lld-19` as the linker backend:

```sh
exec clang-19 \
    --target=aarch64-linux-musl \
    --sysroot="$MUSL_SYSROOT" \   # default: /usr/aarch64-linux-gnu
    -fuse-ld=lld-19 \
    "$@"
```

The `Makefile` prepends the `scripts/` directory to `PATH` automatically, so `cargo build` resolves the wrapper without any manual configuration.

---

## Usage

```bash
stacker <SUBCOMMAND> [OPTIONS]
```

### Commands

- **capture**: Capture stack traces into a JSON file (Phase 1)
  - **options**: `--pid <pid>`, `--output <path>`
  - **example**:
    ```bash
    stacker capture --pid 1234 --output capture.json
    ```

- **symbolize**: Symbolize a previously captured JSON file (Phase 2)
  - **options**: `--input <path>`, `--executable <path>`
  - **example**:
    ```bash
    stacker symbolize --input capture.json --executable /proc/1234/exe
    ```

- **onephase**: Capture and symbolize in one go (no intermediate file)
  - **options**: `--pid <pid>`
  - **example**:
    ```bash
    stacker onephase --pid 1234
    ```

#### Notes on symbolization

- **Shared libraries and debug symbols**: If the traced process uses shared libraries, the exact libraries (and ideally their debug symbol packages) must be installed and discoverable during symbolization, especially when symbolizing on a different machine. Otherwise, symbol resolution may be incomplete or missing file/line information.

- **Two-phase workflow**: The `capture` + `symbolize` split is useful when you want to minimize the time the target process is paused. Capture runs on the production host (stopping the process only briefly), and symbolization can be done later on any machine that has access to the same binaries and debug symbols.

---

## Output

The program displays:

1. **Process information**: PID and architecture being traced
2. **Thread discovery**: Number of threads found
3. **Timing information**: How long the process was stopped
4. **Memory maps**: Process memory layout and loaded libraries
5. **Per-thread information**:
   - Thread ID (TID)
   - Thread name (from `/proc/{pid}/task/{tid}/comm`)
   - CPU registers (architecture-specific)
   - Stack trace with symbol information

### Sample Output

```
Stacker v0.1.0 - Multi-architecture stack tracer
Target architecture: x86_64
Attaching to process 1234
Found 3 threads
Process was stopped for: 2.345ms

Symbolizing stack traces...

=== Thread 1 (TID: 1234, Name: 'main') ===
  Registers (x86_64):
    RAX: 0x00007f8b8c0d4000  RBX: 0x0000000000000000  ...

  #0: 0x00007f8b8c0d4567 in main at src/main.rs:42
  #1: 0x00007f8b8c0d3456 in std::rt::lang_start at /rustc/.../library/std/src/rt.rs:145
  ...
```

---

## Architecture-Specific Details

### x86_64
- **Registers**: Shows RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8–R15, RIP, EFLAGS, segment registers
- **Stack walking**: Uses RBP (frame pointer) to walk stack frames
- **Calling convention**: Follows the x86_64 System V ABI

### ARM64 (aarch64)
- **Registers**: Shows X0–X30, SP, PC, PSTATE
- **Stack walking**: Uses X29 (frame pointer) to walk stack frames
- **Calling convention**: Follows the ARM64 AAPCS calling convention

---

## How It Works

1. **Process Attachment**: Uses ptrace to attach to the target process and all its threads
2. **Register Capture**: Reads CPU registers from each thread using `PTRACE_GETREGS`
3. **Stack Walking**: Follows frame pointers to unwind the call stack
4. **Quick Detachment**: Detaches from all threads to minimize process interruption
5. **Symbol Resolution**: Uses built-in DWARF parsing (`addr2line`, `gimli`, `object`) to resolve addresses to human-readable symbols

---

## Requirements

- Linux operating system
- One of the supported architectures (x86_64 or ARM64)
- Target process with debug symbols for best results
- Sufficient privileges to ptrace the target process (see below)

---

## Limitations

- Requires ptrace permissions — may need to run as root, or relax the kernel's ptrace scope:
  ```bash
  # Allow ptrace of non-child processes (temporary, resets on reboot)
  echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
  ```
- Stack unwinding relies on frame pointers; optimized builds compiled without them (`-fomit-frame-pointer`) will produce incomplete traces
- Symbol resolution depends on debug information availability
- Currently supports Linux only

---

## License

This project is open source. See the source code for details.