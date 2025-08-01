use std::path::Path;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::SymbolizedFrame;

pub struct Symbolizer {
    loader: addr2line::Loader,
    base_address: u64,
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
    pub fn new(executable_path: &str, pid: i32) -> Result<Self, Box<dyn std::error::Error>> {
        // Create loader with the executable path
        let loader = addr2line::Loader::new(Path::new(executable_path))?;
        
        // Find the base address from /proc/PID/maps
        let base_address = Self::find_base_address(pid, executable_path)?;
        
        println!("Symbolizer: Found base address 0x{:x} for {}", base_address, executable_path);
        
        Ok(Symbolizer { loader, base_address })
    }
    
    fn find_base_address(pid: i32, executable_path: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let maps_path = format!("/proc/{}/maps", pid);
        let file = File::open(&maps_path)?;
        let reader = BufReader::new(file);
        
        // Parse /proc/PID/maps to find the base address of the executable
        for line in reader.lines() {
            let line = line?;
            if let Some(mapping) = Self::parse_memory_mapping(&line) {
                // Look for the main executable (usually the first executable mapping)
                if mapping.pathname.contains("exe") || mapping.pathname == executable_path {
                    if mapping.offset == 0 {  // First mapping of the executable
                        return Ok(mapping.start);
                    }
                }
            }
        }
        
        // Fallback: if we can't find it, assume no offset needed
        eprintln!("Warning: Could not find base address for {}, assuming 0", executable_path);
        Ok(0)
    }
    
    fn parse_memory_mapping(line: &str) -> Option<MemoryMapping> {
        // Format: address perms offset dev inode pathname
        // Example: 559a9c400000-559a9c401000 r--p 00000000 103:02 2621487 /path/to/exe
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            return None;
        }
        
        let address_range = parts[0];
        let offset_str = parts[2];
        let pathname = parts[5..].join(" ");
        
        // Parse address range
        let addr_parts: Vec<&str> = address_range.split('-').collect();
        if addr_parts.len() != 2 {
            return None;
        }
        
        let start = u64::from_str_radix(addr_parts[0], 16).ok()?;
        let end = u64::from_str_radix(addr_parts[1], 16).ok()?;
        let offset = u64::from_str_radix(offset_str, 16).ok()?;
        
        Some(MemoryMapping {
            start,
            end,
            offset,
            pathname,
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
        let file_address = if address >= self.base_address {
            address - self.base_address
        } else {
            // Address is below base address, might be in a different mapping
            // For now, try the address as-is
            address
        };

        // Try to find frames (handles inlined functions)
        if let Ok(mut frames) = self.loader.find_frames(file_address) {
            // Get the outermost (non-inlined) frame first
            if let Ok(Some(frame)) = frames.next() {
                // Get function name
                if let Some(function) = frame.function {
                    if let Ok(name) = function.demangle() {
                        result.function_name = Some(name.to_string());
                    } else if let Ok(raw_name) = function.raw_name() {
                        result.function_name = Some(raw_name.to_string());
                    }
                } else {
                    eprintln!("Failed to find function for address: 0x{:x}", address);
                }

                // Get location information
                if let Some(location) = frame.location {
                    if let Some(file) = location.file {
                        result.file_name = Some(file.to_string());
                    }
                    result.line_number = location.line;
                } else {
                    eprintln!("Failed to find location for address: 0x{:x}", address);
                }
            } else {
                eprintln!("Failed to find next frame");
            }
        } else {
            eprintln!("Failed to find frames for address: 0x{:x}", address);
        }

        // Fallback if frames lookup didn't work
        if result.function_name.is_none() {
            if let Ok(Some(location)) = self.loader.find_location(file_address) {
                if let Some(file) = location.file {
                    result.file_name = Some(file.to_string());
                }
                result.line_number = location.line;
            }
        }

        // If still no function name, provide a fallback
        if result.function_name.is_none() {
            result.function_name = Some(format!("<unknown_{address:x}>"));
        }

        result
    }
}
