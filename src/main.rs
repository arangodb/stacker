use std::env;
use std::fs;
use std::time::Instant;

use nix::libc::{c_void, user_regs_struct};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

mod symbolizer;
use symbolizer::Symbolizer;

#[derive(Debug, Clone)]
struct ThreadInfo {
    tid: i32,
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

fn print_x86_64_registers(regs: &user_regs_struct) {
    println!("  Registers:");
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pid>", args[0]);
        std::process::exit(1);
    }

    let pid: i32 = args[1].parse()?;
    println!("Attaching to process {pid}");

    let start_time = Instant::now();
    
    // Step 1: Discover all threads
    let thread_ids = discover_threads(pid)?;
    println!("Found {} threads", thread_ids.len());

    // Step 2: Attach to all threads and capture stack traces quickly
    let thread_infos = capture_all_threads(thread_ids)?;
    
    let capture_duration = start_time.elapsed();
    println!("Process was stopped for: {capture_duration:?}");

    // Step 3: Now we can take our time to symbolize the stack traces
    println!("\nSymbolizing stack traces...");
    let symbolize_start = Instant::now();
    
    let executable_path = format!("/proc/{pid}/exe");
    let symbolizer = Symbolizer::new(&executable_path)?;
    
    for (i, thread_info) in thread_infos.iter().enumerate() {
        println!("\n=== Thread {} (TID: {}) ===", i + 1, thread_info.tid);
        print_x86_64_registers(&thread_info.registers);
        
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
    println!("Total time: {:?}", start_time.elapsed());

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

fn capture_all_threads(thread_ids: Vec<i32>) -> Result<Vec<ThreadInfo>, Box<dyn std::error::Error>> {
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
        if let Ok(thread_info) = capture_thread_stack_trace(tid) {
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

fn capture_thread_stack_trace(tid: i32) -> Result<ThreadInfo, Box<dyn std::error::Error>> {
    let pid = Pid::from_raw(tid);
    
    // Get registers
    let registers = ptrace::getregs(pid)?;
    
    // Get stack trace by walking the stack
    let stack_trace = walk_stack(pid, &registers)?;
    
    Ok(ThreadInfo {
        tid,
        registers,
        stack_trace,
    })
}

fn walk_stack(pid: Pid, registers: &user_regs_struct) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
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

fn read_memory_word(pid: Pid, addr: u64) -> Result<u64, nix::Error> {
    let word = ptrace::read(pid, addr as *mut c_void)?;
    Ok(word as u64)
}
