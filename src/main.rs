use std::env;
use std::fs;
use std::time::Instant;
use std::fs::File;
use std::io::{BufRead, BufReader};

use nix::libc::{c_void, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

// Compile-time architecture verification
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("This program currently supports only x86_64 and aarch64 architectures");

// Architecture info helper
fn get_architecture_info() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return "x86_64";
    #[cfg(target_arch = "aarch64")]
    return "aarch64";
}

mod symbolizer;
use symbolizer::Symbolizer;

#[derive(Debug, Clone)]
struct ThreadInfo {
    tid: i32,
    thread_name: String,
    registers: user_regs_struct,
    stack_trace: Vec<u64>,
}

#[derive(Debug)]
struct SymbolizedFrame {
    address: u64,
    function_name: Option<String>,
    file_name: Option<String>,
    line_number: Option<u32>,
}

#[derive(Debug)]
pub struct MemoryMapping {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub pathname: String,
}

// Architecture-agnostic register printing
#[cfg(target_arch = "x86_64")]
fn print_registers(regs: &user_regs_struct) {
    print_x86_64_registers(regs);
}

#[cfg(target_arch = "aarch64")]
fn print_registers(regs: &user_regs_struct) {
    print_arm64_registers(regs);
}

#[cfg(target_arch = "x86_64")]
fn print_x86_64_registers(regs: &user_regs_struct) {
    println!("  Registers (x86_64):");
    // General purpose registers
    println!("    RAX: 0x{:016x}  RBX: 0x{:016x}  RCX: 0x{:016x}  RDX: 0x{:016x}", 
             regs.rax, regs.rbx, regs.rcx, regs.rdx);
    println!("    RSI: 0x{:016x}  RDI: 0x{:016x}  RBP: 0x{:016x}  RSP: 0x{:016x}", 
             regs.rsi, regs.rdi, regs.rbp, regs.rsp);
    println!("    R8:  0x{:016x}  R9:  0x{:016x}  R10: 0x{:016x}  R11: 0x{:016x}", 
             regs.r8, regs.r9, regs.r10, regs.r11);
    println!("    R12: 0x{:016x}  R13: 0x{:016x}  R14: 0x{:016x}  R15: 0x{:016x}", 
             regs.r12, regs.r13, regs.r14, regs.r15);
    
    // Instruction pointer and flags
    println!("    RIP: 0x{:016x}  EFLAGS: 0x{:016x}", 
             regs.rip, regs.eflags);
    
    // Segment registers
    println!("    CS: 0x{:04x}  SS: 0x{:04x}  DS: 0x{:04x}  ES: 0x{:04x}  FS: 0x{:04x}  GS: 0x{:04x}", 
             regs.cs, regs.ss, regs.ds, regs.es, regs.fs, regs.gs);
    
    // Original RAX and error code (useful for system calls)
    println!("    ORIG_RAX: 0x{:016x}", regs.orig_rax);
}

#[cfg(target_arch = "aarch64")]
fn print_arm64_registers(regs: &user_regs_struct) {
    println!("  Registers (ARM64):");
    // General purpose registers X0-X7
    println!("    X0:  0x{:016x}  X1:  0x{:016x}  X2:  0x{:016x}  X3:  0x{:016x}", 
             regs.regs[0], regs.regs[1], regs.regs[2], regs.regs[3]);
    println!("    X4:  0x{:016x}  X5:  0x{:016x}  X6:  0x{:016x}  X7:  0x{:016x}", 
             regs.regs[4], regs.regs[5], regs.regs[6], regs.regs[7]);
    
    // General purpose registers X8-X15
    println!("    X8:  0x{:016x}  X9:  0x{:016x}  X10: 0x{:016x}  X11: 0x{:016x}", 
             regs.regs[8], regs.regs[9], regs.regs[10], regs.regs[11]);
    println!("    X12: 0x{:016x}  X13: 0x{:016x}  X14: 0x{:016x}  X15: 0x{:016x}", 
             regs.regs[12], regs.regs[13], regs.regs[14], regs.regs[15]);
    
    // General purpose registers X16-X23
    println!("    X16: 0x{:016x}  X17: 0x{:016x}  X18: 0x{:016x}  X19: 0x{:016x}", 
             regs.regs[16], regs.regs[17], regs.regs[18], regs.regs[19]);
    println!("    X20: 0x{:016x}  X21: 0x{:016x}  X22: 0x{:016x}  X23: 0x{:016x}", 
             regs.regs[20], regs.regs[21], regs.regs[22], regs.regs[23]);
    
    // General purpose registers X24-X30
    println!("    X24: 0x{:016x}  X25: 0x{:016x}  X26: 0x{:016x}  X27: 0x{:016x}", 
             regs.regs[24], regs.regs[25], regs.regs[26], regs.regs[27]);
    println!("    X28: 0x{:016x}  X29: 0x{:016x}  X30: 0x{:016x}", 
             regs.regs[28], regs.regs[29], regs.regs[30]);
    
    // Special registers
    println!("    SP:  0x{:016x}  PC:  0x{:016x}  PSTATE: 0x{:016x}", 
             regs.sp, regs.pc, regs.pstate);
}

fn parse_memory_mapping(line: &str) -> Option<MemoryMapping> {
    // Format: address perms offset dev inode pathname
    // Example: 559a9c400000-559a9c401000 r--p 00000000 103:02 2621487 /path/to/exe
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 {
        return None;
    }
    
    let address_range = parts[0];
    let permissions = parts[1].to_string();
    let offset_str = parts[2];
    let device = parts[3].to_string();
    let inode_str = parts[4];
    let pathname = parts[5..].join(" ");
    
    // Parse address range
    let addr_parts: Vec<&str> = address_range.split('-').collect();
    if addr_parts.len() != 2 {
        return None;
    }
    
    let start = u64::from_str_radix(addr_parts[0], 16).ok()?;
    let end = u64::from_str_radix(addr_parts[1], 16).ok()?;
    let offset = u64::from_str_radix(offset_str, 16).ok()?;
    let inode = inode_str.parse::<u64>().ok()?;
    
    Some(MemoryMapping {
        start,
        end,
        permissions,
        offset,
        device,
        inode,
        pathname,
    })
}

fn display_memory_maps(pid: i32) -> Result<(), Box<dyn std::error::Error>> {
    let maps_path = format!("/proc/{pid}/maps");
    let file = File::open(&maps_path)?;
    let reader = BufReader::new(file);
    
    println!("\n=== Memory Maps ===");
    println!("Address Range          Perms  Offset     Device   Inode    Pathname");
    println!("------------------     -----  --------   ------   -------  --------");
    
    for line in reader.lines() {
        let line = line?;
        if let Some(mapping) = parse_memory_mapping(&line) {
            println!("{:016x}-{:016x} {:5} {:08x}   {:6} {:>8}  {}",
                mapping.start,
                mapping.end,
                mapping.permissions,
                mapping.offset,
                mapping.device,
                mapping.inode,
                if mapping.pathname.is_empty() { "[anonymous]" } else { &mapping.pathname }
            );
        }
    }
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pid>", args[0]);
        std::process::exit(1);
    }

    let pid: i32 = args[1].parse()?;
    println!("Stacker v0.1.0 - Multi-architecture stack tracer");
    println!("Target architecture: {}", get_architecture_info());
    println!("Attaching to process {pid}");

    let start_time = Instant::now();
    
    // Step 1: Discover all threads
    let thread_ids = discover_threads(pid)?;
    println!("Found {} threads", thread_ids.len());

    // Step 2: Attach to all threads and capture stack traces quickly
    let thread_infos = capture_all_threads(pid, thread_ids)?;
    
    let capture_duration = start_time.elapsed();
    println!("Process was stopped for: {capture_duration:?}");

    // Step 3: Now we can take our time to symbolize the stack traces
    println!("\nSymbolizing stack traces...");
    let symbolize_start = Instant::now();
    
    let executable_path = format!("/proc/{pid}/exe");
    let mut symbolizer = Symbolizer::new(&executable_path, pid)?;
    
    for (i, thread_info) in thread_infos.iter().enumerate() {
        println!("\n=== Thread {} (TID: {}, Name: '{}') ===", i + 1, thread_info.tid, thread_info.thread_name);
        print_registers(&thread_info.registers);
        
        for (frame_idx, &addr) in thread_info.stack_trace.iter().enumerate() {
            let sym_frame = symbolizer.symbolize(addr);
            
            print!("  #{}: 0x{:016x}", frame_idx, sym_frame.address);
            
            if let Some(ref func_name) = sym_frame.function_name {
                print!(" in {func_name}");
            }
            
            if let Some(ref file_name) = sym_frame.file_name {
                print!(" at {file_name}");
                if let Some(line_num) = sym_frame.line_number {
                    print!(":{line_num}");
                }
            }
            
            println!();
        }
    }
    
    let symbolize_duration = symbolize_start.elapsed();
    println!("\nSymbolization took: {symbolize_duration:?}");
    
    // Display memory maps
    if let Err(e) = display_memory_maps(pid) {
        eprintln!("Failed to display memory maps: {e}");
    }
    
    println!("\nTotal time: {:?}", start_time.elapsed());

    Ok(())
}

fn discover_threads(pid: i32) -> Result<Vec<i32>, Box<dyn std::error::Error>> {
    let task_dir = format!("/proc/{pid}/task");
    let mut thread_ids = Vec::new();
    
    for entry in fs::read_dir(task_dir)? {
        let entry = entry?;
        if let Ok(tid) = entry.file_name().to_string_lossy().parse::<i32>() {
            thread_ids.push(tid);
        }
    }
    
    thread_ids.sort();
    Ok(thread_ids)
}

fn capture_all_threads(pid: i32, thread_ids: Vec<i32>) -> Result<Vec<ThreadInfo>, Box<dyn std::error::Error>> {
    let mut thread_infos = Vec::new();
    let mut attached_tids = Vec::new();
    
    // Attach to all threads first
    for &tid in &thread_ids {
        match ptrace::attach(Pid::from_raw(tid)) {
            Ok(_) => {
                // Wait for the thread to stop
                match waitpid(Pid::from_raw(tid), None) {
                    Ok(WaitStatus::Stopped(_, _)) => {
                        attached_tids.push(tid);
                    }
                    Ok(status) => {
                        eprintln!("Unexpected wait status for TID {tid}: {status:?}");
                    }
                    Err(e) => {
                        eprintln!("Failed to wait for TID {tid}: {e}");
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to attach to TID {tid}: {e}");
            }
        }
    }
    
    // Now quickly capture stack traces for all stopped threads
    for &tid in &attached_tids {
        if let Ok(thread_info) = capture_thread_stack_trace(pid, tid) {
            thread_infos.push(thread_info);
        }
    }
    
    // Detach from all threads to resume the process
    for &tid in &attached_tids {
        if let Err(e) = ptrace::detach(Pid::from_raw(tid), None) {
            eprintln!("Failed to detach from TID {tid}: {e}");
        }
    }
    
    Ok(thread_infos)
}

fn get_thread_name(pid: i32, tid: i32) -> String {
    let comm_path = format!("/proc/{pid}/task/{tid}/comm");
    match fs::read_to_string(&comm_path) {
        Ok(name) => name.trim().to_string(),
        Err(_) => "<unknown>".to_string(),
    }
}

fn capture_thread_stack_trace(main_pid: i32, tid: i32) -> Result<ThreadInfo, Box<dyn std::error::Error>> {
    let pid = Pid::from_raw(tid);
    
    // Get thread name using the main process PID and thread ID
    let thread_name = get_thread_name(main_pid, tid);
    
    // Get registers
    let registers = ptrace::getregs(pid)?;
    
    // Get stack trace by walking the stack
    let stack_trace = walk_stack(pid, &registers)?;
    
    Ok(ThreadInfo {
        tid,
        thread_name,
        registers,
        stack_trace,
    })
}

// Architecture-agnostic stack walking
#[cfg(target_arch = "x86_64")]
fn walk_stack(pid: Pid, registers: &user_regs_struct) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    walk_stack_x86_64(pid, registers)
}

#[cfg(target_arch = "aarch64")]
fn walk_stack(pid: Pid, registers: &user_regs_struct) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    walk_stack_arm64(pid, registers)
}

#[cfg(target_arch = "x86_64")]
fn walk_stack_x86_64(pid: Pid, registers: &user_regs_struct) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let mut stack_trace = Vec::new();
    let rip = registers.rip;
    let mut rbp = registers.rbp;
    
    // Add the current instruction pointer
    stack_trace.push(rip);
    
    // Walk the stack frames (simplified stack walking)
    const MAX_FRAMES: usize = 50;
    for _ in 0..MAX_FRAMES {
        if rbp == 0 {
            break;
        }
        
        // Try to read the return address and previous frame pointer
        match read_memory_word(pid, rbp + 8) {
            Ok(return_addr) => {
                if return_addr == 0 {
                    break;
                }
                stack_trace.push(return_addr);
                
                // Read previous frame pointer
                match read_memory_word(pid, rbp) {
                    Ok(prev_rbp) => {
                        if prev_rbp <= rbp {
                            break; // Prevent infinite loops
                        }
                        rbp = prev_rbp;
                    }
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }
    }
    
    Ok(stack_trace)
}

#[cfg(target_arch = "aarch64")]
fn walk_stack_arm64(pid: Pid, registers: &user_regs_struct) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let mut stack_trace = Vec::new();
    let pc = registers.pc;           // Program counter (instruction pointer)
    let mut fp = registers.regs[29]; // Frame pointer (X29 in ARM64)
    
    // Add the current instruction pointer
    stack_trace.push(pc);
    
    // Walk the stack frames using ARM64 calling convention
    // ARM64 stack frame layout:
    // [FP-16] = previous frame's LR (return address)
    // [FP-8]  = previous frame's FP
    // [FP]    = current frame pointer
    const MAX_FRAMES: usize = 50;
    for _ in 0..MAX_FRAMES {
        if fp == 0 {
            break;
        }
        
        // ARM64: Read the return address from [FP + 8] (link register save location)
        match read_memory_word(pid, fp + 8) {
            Ok(return_addr) => {
                if return_addr == 0 {
                    break;
                }
                stack_trace.push(return_addr);
                
                // Read previous frame pointer from [FP]
                match read_memory_word(pid, fp) {
                    Ok(prev_fp) => {
                        if prev_fp <= fp {
                            break; // Prevent infinite loops
                        }
                        fp = prev_fp;
                    }
                    Err(_) => break,
                }
            }
            Err(_) => break,
        }
    }
    
    Ok(stack_trace)
}

fn read_memory_word(pid: Pid, addr: u64) -> Result<u64, nix::Error> {
    let word = ptrace::read(pid, addr as *mut c_void)?;
    Ok(word as u64)
}
