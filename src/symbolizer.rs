use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use crate::SymbolizedFrame;

pub struct Symbolizer {
    process: Mutex<Child>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct MemoryMapping {
    start: u64,
    end: u64,
    offset: u64,
    pathname: String,
}

impl Symbolizer {
    pub fn new(executable_path: &str, _pid: i32) -> Result<Self, Box<dyn std::error::Error>> {
        // Start addr2line process
        let process = Command::new("addr2line")
            .arg("-e")
            .arg(executable_path)
            .arg("-f") // Include function names
            .arg("-C") // Demangle C++ names
            .arg("-p") // Pretty print (more readable format)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Verify process started successfully
        if process.stdin.is_none() || process.stdout.is_none() {
            return Err("Failed to create pipes to addr2line process".into());
        }

        Ok(Symbolizer {
            process: Mutex::new(process),
        })
    }

    pub fn symbolize(&self, address: u64) -> SymbolizedFrame {
        let mut result = SymbolizedFrame {
            address,
            function_name: None,
            file_name: None,
            line_number: None,
        };

        // Convert virtual address to file offset
        let file_address = address;

        // Send address to addr2line and read response
        if let Ok(mut process_guard) = self.process.lock() {
            let process = &mut *process_guard;

            if let (Some(stdin), Some(stdout)) = (process.stdin.as_mut(), process.stdout.as_mut()) {
                // Send the address
                if let Err(e) = writeln!(stdin, "0x{file_address:x}") {
                    eprintln!("Failed to write address to addr2line: {e}");
                    result.function_name = Some(format!("<unknown_{address:x}>"));
                    return result;
                }

                if let Err(e) = stdin.flush() {
                    eprintln!("Failed to flush stdin to addr2line: {e}");
                    result.function_name = Some(format!("<unknown_{address:x}>"));
                    return result;
                }

                // Read the response
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();

                if reader.read_line(&mut line).is_ok() {
                    let line = line.trim();

                    // Parse the response format: "function at file:line" or "?? ??:0"
                    if line.contains(" at ") {
                        let parts: Vec<&str> = line.splitn(2, " at ").collect();
                        if parts.len() == 2 {
                            let function_name = parts[0].trim();
                            let location = parts[1].trim();

                            // Set function name (skip if it's "??")
                            if function_name != "??" {
                                result.function_name = Some(function_name.to_string());
                            }

                            // Parse file:line
                            if let Some(colon_pos) = location.rfind(':') {
                                let file_part = &location[..colon_pos];
                                let line_part = &location[colon_pos + 1..];

                                if file_part != "??" {
                                    result.file_name = Some(file_part.to_string());
                                }

                                if let Ok(line_num) = line_part.parse::<u32>() {
                                    if line_num > 0 {
                                        result.line_number = Some(line_num);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    eprintln!("Failed to read response from addr2line for address: 0x{address:x}");
                }
            } else {
                eprintln!("addr2line process pipes not available");
            }
        } else {
            eprintln!("Failed to lock addr2line process");
        }

        // If still no function name, provide a fallback
        if result.function_name.is_none() {
            result.function_name = Some(format!("<unknown_{address:x}>"));
        }

        result
    }
}

impl Drop for Symbolizer {
    fn drop(&mut self) {
        // Clean up the addr2line process
        if let Ok(mut process_guard) = self.process.lock() {
            let process = &mut *process_guard;

            // Close stdin to signal the process to exit
            if let Some(mut stdin) = process.stdin.take() {
                let _ = stdin.flush();
                drop(stdin);
            }

            // Try to terminate the process gracefully
            let _ = process.wait();
        }
    }
}
