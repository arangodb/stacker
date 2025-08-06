use std::fs;
use std::time::Instant;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::collections::HashMap;

use nix::libc::{c_void, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

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

#[derive(Parser)]
#[command(name = "stacker")]
#[command(about = "Multi-architecture stack tracer with two-phase operation")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Capture stack traces from a running process (Phase 1)
    Capture {
        /// Process ID to attach to
        #[arg(short, long)]
        pid: i32,
        /// Output JSON file path
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Symbolize captured stack traces (Phase 2)
    Symbolize {
        /// Input JSON file from capture phase
        #[arg(short, long)]
        input: PathBuf,
        /// Path to the executable for symbolization
        #[arg(short, long)]
        executable: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableRegisters {
    #[cfg(target_arch = "x86_64")]
    pub rax: u64,
    #[cfg(target_arch = "x86_64")]
    pub rbx: u64,
    #[cfg(target_arch = "x86_64")]
    pub rcx: u64,
    #[cfg(target_arch = "x86_64")]
    pub rdx: u64,
    #[cfg(target_arch = "x86_64")]
    pub rsi: u64,
    #[cfg(target_arch = "x86_64")]
    pub rdi: u64,
    #[cfg(target_arch = "x86_64")]
    pub rbp: u64,
    #[cfg(target_arch = "x86_64")]
    pub rsp: u64,
    #[cfg(target_arch = "x86_64")]
    pub r8: u64,
    #[cfg(target_arch = "x86_64")]
    pub r9: u64,
    #[cfg(target_arch = "x86_64")]
    pub r10: u64,
    #[cfg(target_arch = "x86_64")]
    pub r11: u64,
    #[cfg(target_arch = "x86_64")]
    pub r12: u64,
    #[cfg(target_arch = "x86_64")]
    pub r13: u64,
    #[cfg(target_arch = "x86_64")]
    pub r14: u64,
    #[cfg(target_arch = "x86_64")]
    pub r15: u64,
    #[cfg(target_arch = "x86_64")]
    pub rip: u64,
    #[cfg(target_arch = "x86_64")]
    pub eflags: u64,
    #[cfg(target_arch = "x86_64")]
    pub cs: u16,
    #[cfg(target_arch = "x86_64")]
    pub ss: u16,
    #[cfg(target_arch = "x86_64")]
    pub ds: u16,
    #[cfg(target_arch = "x86_64")]
    pub es: u16,
    #[cfg(target_arch = "x86_64")]
    pub fs: u16,
    #[cfg(target_arch = "x86_64")]
    pub gs: u16,
    #[cfg(target_arch = "x86_64")]
    pub orig_rax: u64,

    #[cfg(target_arch = "aarch64")]
    pub regs: [u64; 31],
    #[cfg(target_arch = "aarch64")]
    pub sp: u64,
    #[cfg(target_arch = "aarch64")]
    pub pc: u64,
    #[cfg(target_arch = "aarch64")]
    pub pstate: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapturedThreadInfo {
    tid: i32,
    thread_name: String,
    registers: SerializableRegisters,
    stack_trace: Vec<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CaptureData {
    timestamp: DateTime<Utc>,
    architecture: String,
    process_id: i32,
    executable_path: String,
    memory_maps: Vec<MemoryMapping>,
    file_base_addresses: HashMap<String, u64>,
    threads: Vec<CapturedThreadInfo>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

fn parse_memory_maps(pid: i32) -> Result<Vec<MemoryMapping>, Box<dyn std::error::Error>> {
    let maps_path = format!("/proc/{pid}/maps");
    let file = File::open(&maps_path)?;
    let reader = BufReader::new(file);
    
    let mut mappings = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if let Some(mapping) = parse_memory_mapping(&line) {
            mappings.push(mapping);
        }
    }
    
    Ok(mappings)
}

fn extract_file_base_addresses(memory_maps: &[MemoryMapping]) -> HashMap<String, u64> {
    let mut file_base_addresses = HashMap::new();
    
    for mapping in memory_maps {
        // Skip mappings with no filename or empty filename
        if mapping.pathname.is_empty() || mapping.pathname.starts_with('[') {
            continue;
        }
        
        // Only insert if we haven't seen this file before (first mapping = base address)
        if !file_base_addresses.contains_key(&mapping.pathname) {
            file_base_addresses.insert(mapping.pathname.clone(), mapping.start);
        }
    }
    
    file_base_addresses
}

fn display_memory_maps_from_data(mappings: &[MemoryMapping]) {
    println!("\n=== Memory Maps ===");
    println!("Address Range          Perms  Offset     Device   Inode    Pathname");
    println!("------------------     -----  --------   ------   -------  --------");
    
    for mapping in mappings {
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

// Convert user_regs_struct to SerializableRegisters
impl From<user_regs_struct> for SerializableRegisters {
    fn from(regs: user_regs_struct) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            SerializableRegisters {
                rax: regs.rax,
                rbx: regs.rbx,
                rcx: regs.rcx,
                rdx: regs.rdx,
                rsi: regs.rsi,
                rdi: regs.rdi,
                rbp: regs.rbp,
                rsp: regs.rsp,
                r8: regs.r8,
                r9: regs.r9,
                r10: regs.r10,
                r11: regs.r11,
                r12: regs.r12,
                r13: regs.r13,
                r14: regs.r14,
                r15: regs.r15,
                rip: regs.rip,
                eflags: regs.eflags,
                cs: regs.cs as u16,
                ss: regs.ss as u16,
                ds: regs.ds as u16,
                es: regs.es as u16,
                fs: regs.fs as u16,
                gs: regs.gs as u16,
                orig_rax: regs.orig_rax,
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            SerializableRegisters {
                regs: regs.regs,
                sp: regs.sp,
                pc: regs.pc,
                pstate: regs.pstate,
            }
        }
    }
}

// Convert SerializableRegisters to user_regs_struct
impl From<SerializableRegisters> for user_regs_struct {
    fn from(regs: SerializableRegisters) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            user_regs_struct {
                rax: regs.rax,
                rbx: regs.rbx,
                rcx: regs.rcx,
                rdx: regs.rdx,
                rsi: regs.rsi,
                rdi: regs.rdi,
                rbp: regs.rbp,
                rsp: regs.rsp,
                r8: regs.r8,
                r9: regs.r9,
                r10: regs.r10,
                r11: regs.r11,
                r12: regs.r12,
                r13: regs.r13,
                r14: regs.r14,
                r15: regs.r15,
                rip: regs.rip,
                eflags: regs.eflags,
                cs: regs.cs as u64,
                ss: regs.ss as u64,
                ds: regs.ds as u64,
                es: regs.es as u64,
                fs: regs.fs as u64,
                gs: regs.gs as u64,
                orig_rax: regs.orig_rax,
                fs_base: 0,
                gs_base: 0,
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            user_regs_struct {
                regs: regs.regs,
                sp: regs.sp,
                pc: regs.pc,
                pstate: regs.pstate,
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Capture { pid, output } => {
            capture_phase(pid, output)
        }
        Commands::Symbolize { input, executable } => {
            symbolize_phase(input, executable)
        }
    }
}

fn capture_phase(pid: i32, output_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Stacker v0.1.0 - Multi-architecture stack tracer");
    println!("Target architecture: {}", get_architecture_info());
    println!("=== CAPTURE PHASE ===");
    println!("Attaching to process {pid}");

    let start_time = Instant::now();
    
    // Step 1: Get executable path before we start
    let executable_path = fs::read_link(format!("/proc/{pid}/exe"))?
        .to_string_lossy()
        .to_string();
    println!("Executable: {executable_path}");
    
    // Step 2: Parse memory maps
    let memory_maps = parse_memory_maps(pid)?;
    
    // Step 3: Extract file base addresses from memory maps
    let file_base_addresses = extract_file_base_addresses(&memory_maps);
    
    // Step 4: Discover all threads
    let thread_ids = discover_threads(pid)?;
    println!("Found {} threads", thread_ids.len());

    // Step 5: Attach to all threads and capture stack traces quickly
    let thread_infos = capture_all_threads(pid, thread_ids)?;
    
    let capture_duration = start_time.elapsed();
    println!("Process was stopped for: {capture_duration:?}");

    // Step 6: Convert to serializable format
    let captured_threads: Vec<CapturedThreadInfo> = thread_infos
        .into_iter()
        .map(|thread| CapturedThreadInfo {
            tid: thread.tid,
            thread_name: thread.thread_name,
            registers: thread.registers.into(),
            stack_trace: thread.stack_trace,
        })
        .collect();

    // Step 7: Create capture data structure
    let capture_data = CaptureData {
        timestamp: Utc::now(),
        architecture: get_architecture_info().to_string(),
        process_id: pid,
        executable_path,
        memory_maps,
        file_base_addresses,
        threads: captured_threads,
    };

    // Step 8: Save to JSON file
    let json_data = serde_json::to_string_pretty(&capture_data)?;
    fs::write(&output_path, json_data)?;
    
    println!("Captured data saved to: {}", output_path.display());
    println!("Total capture time: {:?}", start_time.elapsed());
    println!("\nTo symbolize on another machine:");
    println!("  stacker symbolize --input {} --executable /path/to/executable", output_path.display());

    Ok(())
}

fn symbolize_phase(input_path: PathBuf, executable_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Stacker v0.1.0 - Multi-architecture stack tracer");
    println!("=== SYMBOLIZE PHASE ===");
    
    // Step 1: Load capture data
    println!("Loading capture data from: {}", input_path.display());
    let json_data = fs::read_to_string(&input_path)?;
    let capture_data: CaptureData = serde_json::from_str(&json_data)?;
    
    println!("Loaded capture from: {}", capture_data.timestamp);
    println!("Target architecture: {}", capture_data.architecture);
    println!("Original PID: {}", capture_data.process_id);
    println!("Original executable: {}", capture_data.executable_path);
    println!("Using executable: {}", executable_path.display());
    
    // Step 2: Create symbolizer using provided executable
    println!("\nSymbolizing stack traces...");
    let symbolize_start = Instant::now();
    
    // Create symbolizer with memory maps and file base addresses
    let mut symbolizer = Symbolizer::new_from_data(&executable_path.to_string_lossy(), &capture_data.memory_maps, &capture_data.file_base_addresses)?;
    
    // Step 3: Symbolize each thread
    for (i, captured_thread) in capture_data.threads.iter().enumerate() {
        println!("\n=== Thread {} (TID: {}, Name: '{}') ===", i + 1, captured_thread.tid, captured_thread.thread_name);
        
        // Convert back to user_regs_struct for printing
        let registers: user_regs_struct = captured_thread.registers.clone().into();
        print_registers(&registers);
        
        for (frame_idx, &addr) in captured_thread.stack_trace.iter().enumerate() {
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
    display_memory_maps_from_data(&capture_data.memory_maps);

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
