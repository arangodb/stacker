# Stacker

A multi-architecture stack tracer for Linux processes that supports both x86_64 and ARM64 architectures.

## Features

- **Multi-architecture support**: Works on both x86_64 and ARM64 (aarch64) Linux systems
- **Thread discovery**: Automatically finds and traces all threads in a target process
- **Register dumping**: Shows architecture-specific CPU registers for each thread
- **Stack unwinding**: Walks the call stack using architecture-appropriate methods
- **Symbol resolution**: Resolves addresses to function names, file names, and line numbers using `addr2line`
- **Minimal process interruption**: Quickly captures stack traces and detaches to minimize impact

## Supported Architectures

- **x86_64**: Full support with x86_64-specific register names and stack walking
- **ARM64 (aarch64)**: Full support with ARM64-specific register names and stack walking

## Dependencies

- Linux kernel with ptrace support
- `addr2line` utility (from binutils) for symbol resolution
- Rust toolchain

## Building

```bash
cargo build --release
```

The program will automatically compile with the appropriate architecture-specific code based on your target platform.

## Usage

```bash
./target/release/stacker <pid>
```

Where `<pid>` is the process ID you want to trace.

### Example

```bash
# Trace process with PID 1234
./target/release/stacker 1234
```

## Output

The program displays:

1. **Process information**: PID and architecture being traced
2. **Thread discovery**: Number of threads found
3. **Timing information**: How long the process was stopped
4. **Per-thread information**:
   - Thread ID (TID)
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

=== Thread 1 (TID: 1234) ===
  Registers (x86_64):
    RAX: 0x00007f8b8c0d4000  RBX: 0x0000000000000000  ...
    
  #0: 0x00007f8b8c0d4567 in main at src/main.rs:42
  #1: 0x00007f8b8c0d3456 in std::rt::lang_start at /rustc/.../library/std/src/rt.rs:145
  ...
```

## Architecture-Specific Details

### x86_64
- **Registers**: Shows RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15, RIP, EFLAGS, segment registers
- **Stack walking**: Uses RBP (frame pointer) to walk the stack frames
- **Calling convention**: Follows x86_64 System V ABI

### ARM64 (aarch64)
- **Registers**: Shows X0-X30, SP, PC, PSTATE
- **Stack walking**: Uses X29 (frame pointer) to walk the stack frames  
- **Calling convention**: Follows ARM64 AAPCS calling convention

## How It Works

1. **Process Attachment**: Uses ptrace to attach to the target process and all its threads
2. **Register Capture**: Reads CPU registers from each thread using `PTRACE_GETREGS`
3. **Stack Walking**: Follows frame pointers to unwind the call stack
4. **Quick Detachment**: Detaches from all threads to minimize process interruption
5. **Symbol Resolution**: Uses `addr2line` to resolve addresses to human-readable symbols

## Requirements

- Linux operating system
- One of the supported architectures (x86_64 or ARM64)
- Target process with debug symbols for best results
- Sufficient privileges to ptrace the target process

## Limitations

- Requires ptrace permissions (may need to run as root or adjust ptrace_scope)
- Stack unwinding may not work for all calling conventions or optimized code
- Symbol resolution depends on debug information availability
- Currently supports Linux only

## Cross-Compilation

To build for a different architecture:

```bash
# For ARM64 from x86_64
cargo build --target aarch64-unknown-linux-gnu

# For x86_64 from ARM64  
cargo build --target x86_64-unknown-linux-gnu
```

## License

This project is open source. See the source code for details.