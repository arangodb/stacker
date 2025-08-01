use std::borrow::Cow;
use std::fs;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

use crate::{SymbolizedFrame, MemoryMapping};

struct LibraryInfo {
    context: addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
    _file_data: &'static [u8],
    base_address: u64,
}

#[derive(Clone)]
struct SymbolInfo {
    name: String,
    address: u64,
    size: u64,
}

pub struct Symbolizer {
    main_context: addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
    _main_file_data: &'static [u8],
    symbols: Vec<SymbolInfo>,
    libraries: HashMap<String, LibraryInfo>,
    memory_maps: Vec<MemoryMapping>,
}

impl Symbolizer {
    pub fn new(executable_path: &str, pid: i32) -> Result<Self, Box<dyn std::error::Error>> {
        // Read the executable file
        let file_data = fs::read(executable_path)?;
        
        // Leak the file data to get 'static lifetime
        // This is intentional - we need the data to live for the entire program duration
        let static_file_data: &'static [u8] = Box::leak(file_data.into_boxed_slice());
        
        // Parse the object file
        let object = object::File::parse(static_file_data)?;
        
        // Load debug sections and create DWARF info
        let main_context = Self::create_context_from_object(&object)?;

        // Load symbols from the main executable
        let symbols = Self::load_symbols(&object)?;

        // Parse memory maps to find shared libraries
        let memory_maps = Self::parse_memory_maps(pid)?;

        Ok(Symbolizer {
            main_context,
            _main_file_data: static_file_data,
            symbols,
            libraries: HashMap::new(),
            memory_maps,
        })
    }

    fn create_context_from_object(object: &object::File) -> Result<addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>, Box<dyn std::error::Error>> {
        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        let load_section = |id: gimli::SectionId| -> Result<gimli::EndianRcSlice<gimli::RunTimeEndian>, gimli::Error> {
            let data = match object.section_by_name(id.name()) {
                Some(section) => section.uncompressed_data().unwrap_or(Cow::Borrowed(&[][..])),
                None => Cow::Borrowed(&[][..]),
            };
            Ok(gimli::EndianRcSlice::new(std::rc::Rc::from(&*data), endian))
        };

        let dwarf = gimli::Dwarf::load(&load_section)?;
        Ok(addr2line::Context::from_dwarf(dwarf)?)
    }

    fn load_symbols(object: &object::File) -> Result<Vec<SymbolInfo>, Box<dyn std::error::Error>> {
        let mut symbols = Vec::new();
        
        // Load regular symbols
        for symbol in object.symbols() {
            if let Ok(name) = symbol.name() {
                if !name.is_empty() && symbol.kind() == SymbolKind::Text {
                    symbols.push(SymbolInfo {
                        name: name.to_string(),
                        address: symbol.address(),
                        size: symbol.size(),
                    });
                }
            }
        }

        // Load dynamic symbols (fallback)
        for symbol in object.dynamic_symbols() {
            if let Ok(name) = symbol.name() {
                if !name.is_empty() && symbol.kind() == SymbolKind::Text {
                    // Only add if we don't already have this symbol
                    if !symbols.iter().any(|s| s.name == name && s.address == symbol.address()) {
                        symbols.push(SymbolInfo {
                            name: name.to_string(),
                            address: symbol.address(),
                            size: symbol.size(),
                        });
                    }
                }
            }
        }

        // Sort symbols by address for efficient lookup
        symbols.sort_by_key(|s| s.address);

        eprintln!("Loaded {} symbols from symbol table", symbols.len());
        
        Ok(symbols)
    }

    fn find_symbol_for_address(&self, address: u64) -> Option<&SymbolInfo> {
        // Use binary search to find the symbol that contains this address
        // Since symbols are sorted by address, we need to find the largest address <= target
        match self.symbols.binary_search_by_key(&address, |s| s.address) {
            Ok(index) => Some(&self.symbols[index]),
            Err(insert_index) => {
                if insert_index > 0 {
                    let candidate = &self.symbols[insert_index - 1];
                    // Check if the address falls within this symbol's range
                    if candidate.size > 0 && address < candidate.address + candidate.size {
                        Some(candidate)
                    } else if candidate.size == 0 && address >= candidate.address {
                        // For symbols with unknown size, assume they extend to the next symbol
                        if insert_index < self.symbols.len() {
                            let next_symbol = &self.symbols[insert_index];
                            if address < next_symbol.address {
                                Some(candidate)
                            } else {
                                None
                            }
                        } else {
                            // Last symbol, assume it's valid
                            Some(candidate)
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }

    fn parse_memory_maps(pid: i32) -> Result<Vec<MemoryMapping>, Box<dyn std::error::Error>> {
        let maps_path = format!("/proc/{pid}/maps");
        let file = File::open(&maps_path)?;
        let reader = BufReader::new(file);
        
        let mut mappings = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if let Some(mapping) = Self::parse_memory_mapping(&line) {
                mappings.push(mapping);
            }
        }
        
        Ok(mappings)
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

    fn find_library_for_address(&self, address: u64) -> Option<&MemoryMapping> {
        self.memory_maps.iter().find(|mapping| {
            address >= mapping.start && address < mapping.end && 
            mapping.permissions.contains('x') && // Executable
            !mapping.pathname.is_empty() &&
            mapping.pathname != "[vdso]" &&
            mapping.pathname != "[vsyscall]"
        })
    }

    fn load_library(&mut self, path: &str, base_address: u64) -> Result<(), Box<dyn std::error::Error>> {
        if self.libraries.contains_key(path) {
            return Ok(());
        }

        // Try to read the library file
        let file_data = match fs::read(path) {
            Ok(data) => data,
            Err(_) => {
                // If we can't read the library, skip it
                return Ok(());
            }
        };
        
        let static_file_data: &'static [u8] = Box::leak(file_data.into_boxed_slice());
        
        // Parse the object file
        let object = match object::File::parse(static_file_data) {
            Ok(obj) => obj,
            Err(_) => return Ok(()), // Skip if we can't parse
        };
        
        // Create context
        let context = match Self::create_context_from_object(&object) {
            Ok(ctx) => ctx,
            Err(_) => return Ok(()), // Skip if no debug info
        };

        let lib_info = LibraryInfo {
            context,
            _file_data: static_file_data,
            base_address,
        };

        self.libraries.insert(path.to_string(), lib_info);
        Ok(())
    }

    pub fn symbolize(&mut self, address: u64) -> SymbolizedFrame {
        let mut result = SymbolizedFrame {
            address,
            function_name: None,
            file_name: None,
            line_number: None,
        };

        // For return addresses in stack traces, we usually want to subtract 1
        // to get the actual call site rather than the return address
        let lookup_address = if address > 0 { address - 1 } else { address };

        // Try to find which library this address belongs to
        let mapping_info = self.find_library_for_address(address).map(|m| (m.pathname.clone(), m.start));
        
        if let Some((pathname, base_addr)) = mapping_info {
            if !pathname.is_empty() && !pathname.starts_with('[') {
                // This is a shared library - load it if we haven't already
                if let Err(e) = self.load_library(&pathname, base_addr) {
                    eprintln!("Failed to load library {}: {e}", pathname);
                }
                
                // Try to symbolize using the library
                if let Some(lib_info) = self.libraries.get(&pathname) {
                    // Adjust address relative to library base
                    let relative_address = lookup_address - lib_info.base_address;
                    
                    if let Some(symbolized) = self.try_symbolize_with_context(&lib_info.context, relative_address, address) {
                        return symbolized;
                    }
                }
            }
        }
        
        // Fall back to main executable
        if let Some(symbolized) = self.try_symbolize_with_context(&self.main_context, lookup_address, address) {
            return symbolized;
        }

        // Fall back to symbol table lookup
        if let Some(symbol) = self.find_symbol_for_address(address) {
            result.function_name = Some(symbol.name.clone());
            return result;
        }

        // If still no function name, provide a fallback
        result.function_name = Some(format!("<unknown_{address:x}>"));
        result
    }

    fn try_symbolize_with_context(&self, context: &addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>, lookup_address: u64, original_address: u64) -> Option<SymbolizedFrame> {
        let mut result = SymbolizedFrame {
            address: original_address,
            function_name: None,
            file_name: None,
            line_number: None,
        };

        // Try to find location information for this address
        match context.find_location(lookup_address) {
            Ok(Some(location)) => {
                // Extract file information
                if let Some(file) = location.file {
                    result.file_name = Some(file.to_string());
                }
                
                // Extract line number
                if let Some(line) = location.line {
                    result.line_number = Some(line);
                }
            }
            Ok(None) => {
                // No location information found
            }
            Err(_) => {
                // Error finding location - continue to try frames
            }
        }

        // Try to find function information for this address
        match context.find_frames(lookup_address) {
            addr2line::LookupResult::Output(result_frames) => {
                match result_frames {
                    Ok(mut frames) => {
                        // Process the first frame (there might be multiple due to inlining)
                        if let Ok(Some(frame)) = frames.next() {
                            if let Some(function) = frame.function {
                                // Get the raw function name
                                let raw_name = function.raw_name().unwrap_or(Cow::Borrowed("<unknown>"));
                                
                                // Try to demangle the name
                                let demangled_name = function.demangle().unwrap_or(raw_name);
                                result.function_name = Some(demangled_name.to_string());
                            }
                            
                            // If we didn't get location info before, try to get it from the frame
                            if result.file_name.is_none() {
                                if let Some(location) = frame.location {
                                    if let Some(file) = location.file {
                                        result.file_name = Some(file.to_string());
                                    }
                                    if let Some(line) = location.line {
                                        result.line_number = Some(line);
                                    }
                                }
                            }
                            
                            // Return the result if we found something
                            if result.function_name.is_some() || result.file_name.is_some() {
                                return Some(result);
                            }
                        }
                    }
                    Err(_) => {
                        // Error processing frames
                    }
                }
            },
            addr2line::LookupResult::Load { load: _, continuation: _ } => {
                // Skip lazy loading for now
            }
        }

        None
    }
}

