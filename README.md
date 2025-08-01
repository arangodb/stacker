# Stacker

A fast, lightweight stack trace capture tool for Linux processes written in Rust. Stacker allows you to quickly capture and symbolize stack traces from all threads of a running process with minimal interruption to the target process.

## Features

- **Fast Process Capture**: Quickly attaches to all threads, captures stack traces, and detaches to minimize target process downtime
- **Multi-threaded Support**: Discovers and captures stack traces from all threads in the target process
- **Register Dumps**: Captures and displays x86_64 CPU registers for each thread
- **Symbol Resolution**: Resolves addresses to function names, file names, and line numbers using DWARF debug information
- **Memory Mapping Analysis**: Automatically finds the correct base address for address translation
- **Minimal Dependencies**: Uses the system's `addr2line` utility for symbolization

## Prerequisites

### System Requirements

- **Linux**: This tool uses Linux-specific features like `ptrace` and `/proc` filesystem
- **x86_64 Architecture**: Currently supports x86_64 register dumps and stack walking
- **addr2line**: The GNU `addr2line` utility must be installed on your system

### Installing addr2line

On most Linux distributions, `addr2line` is part of the `binutils` package:

```bash
# Ubuntu/Debian
sudo apt install binutils

# CentOS/RHEL/Fedora
sudo yum install binutils
# or
sudo dnf install binutils

# Arch Linux
sudo pacman -S binutils
```

### DWARF Debugging Information

For meaningful symbolization, the target process must be compiled with DWARF debugging information:

- **Rust programs**: Compile with debug info using `cargo build` (debug builds include debug info by default)
- **C/C++ programs**: Compile with `-g` flag (e.g., `gcc -g` or `clang -g`)
- **For release builds**: You can include debug info in optimized builds:
  - Rust: Add `debug = true` to your `Cargo.toml` release profile
  - C/C++: Use `-g -O2` to combine optimization with debug info

## Installation

### From Source

```bash
git clone <repository-url>
cd stacker
cargo build --release
```

The binary will be available at `target/release/stacker`.

## Usage

```bash
# Basic usage - attach to process by PID
stacker <pid>

# Example
stacker 1234
```

### Example Output

```
Attaching to process 1234
Found 4 threads
Process was stopped for: 23.456ms

Symbolizing stack traces...

=== Thread 1 (TID: 1234) ===
  Registers:
    RAX: 0x00007f8b2c001010  RBX: 0x0000000000000000  RCX: 0x00007f8b2c001010  RDX: 0x0000000000000040
    RSI: 0x00007ffe9c8b5c70  RDI: 0x0000000000000000  RBP: 0x00007ffe9c8b5ca0  RSP: 0x00007ffe9c8b5c50
    R8:  0x0000000000000000  R9:  0x00007f8b2c001010  R10: 0x0000000000000000  R11: 0x0000000000000246
    R12: 0x0000000000000000  R13: 0x00007ffe9c8b5d78  R14: 0x0000000000000000  R15: 0x0000000000000000
    RIP: 0x00007f8b2b8f4a7d  EFLAGS: 0x0000000000000246
    CS: 0x0033  SS: 0x002b  DS: 0x0000  ES: 0x0000  FS: 0x0000  GS: 0x0000
    ORIG_RAX: 0x00000000000000ca

  #0: 0x00007f8b2b8f4a7d in __futex_abstimed_wait_common at futex-internal.h:183
  #1: 0x00007f8b2b8f4b5e in __pthread_cond_wait_common at pthread_cond_wait.c:508
  #2: 0x0000555a1c4d2a3b in main at main.rs:42
  #3: 0x00007f8b2b829083 in __libc_start_main at libc-start.c:308

=== Thread 2 (TID: 1235) ===
...

Symbolization took: 145.234ms
Total time: 168.690ms
```

## How It Works

1. **Thread Discovery**: Scans `/proc/<pid>/task/` to find all thread IDs
2. **Quick Capture**: Uses `ptrace` to attach to all threads simultaneously
3. **Stack Walking**: Performs frame pointer-based stack walking to capture return addresses
4. **Register Capture**: Reads CPU registers using `ptrace(PTRACE_GETREGS)`
5. **Process Resume**: Detaches from all threads to let the process continue normally
6. **Symbolization**: Uses `addr2line` with the process executable to resolve addresses

The tool is designed to minimize the time the target process is stopped. The capture phase typically takes only a few milliseconds, while the symbolization (which doesn't require the process to be stopped) can take longer.

## Architecture

- **`main.rs`**: Core functionality including process attachment, thread discovery, and stack walking
- **`symbolizer.rs`**: Interface to the `addr2line` utility for address-to-symbol resolution

## Dependencies

- **[nix](https://crates.io/crates/nix)**: Low-level Unix system calls (ptrace, process management)
- **[backtrace](https://crates.io/crates/backtrace)**: Backtrace capture utilities
- **[gimli](https://crates.io/crates/gimli)**: DWARF debugging format library
- **[object](https://crates.io/crates/object)**: Object file parsing
- **[symbolic](https://crates.io/crates/symbolic)**: Symbol resolution utilities

## Permissions

This tool requires the ability to attach to other processes using `ptrace`. You may need to:

1. **Run as root** for unrestricted access to all processes
2. **Set ptrace scope** (as root): `echo 0 > /proc/sys/kernel/yama/ptrace_scope`
3. **Use capabilities**: Grant `CAP_SYS_PTRACE` capability to the binary

## Limitations

- **x86_64 only**: Currently only supports x86_64 architecture
- **Linux only**: Uses Linux-specific APIs and filesystem interfaces
- **Frame pointer walking**: Stack walking relies on frame pointers; may not work with `-fomit-frame-pointer`
- **Simple stack walking**: Uses basic frame pointer walking, not as robust as libunwind

## Troubleshooting

### "Permission denied" when attaching to process
- Ensure you have permission to attach to the target process
- Try running as root or adjusting ptrace scope
- Check that the process is still running

### "addr2line: command not found"
- Install binutils package containing addr2line
- Ensure addr2line is in your PATH

### No symbols in output
- Verify the target binary was compiled with debug information (`-g` flag)
- Check that the binary hasn't been stripped of debug symbols
- Ensure the binary path in `/proc/<pid>/exe` is accessible

### Stack traces are incomplete or incorrect
- The target binary may have been compiled with frame pointer omission
- Consider using more robust unwinding methods for production debugging

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.