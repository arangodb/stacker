use std::borrow::Cow;
use std::fs;
use std::collections::HashMap;
use std::path::Path;

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

use crate::{SymbolizedFrame, MemoryMapping};

struct LibraryInfo {
    loader: Option<addr2line::Loader>,
    context: Option<addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>>,
    _file_data: &'static [u8],
    _base_address: u64,
    symbols: Vec<SymbolInfo>,   // sorted, addresses relative to base address!
    #[allow(dead_code)]
    build_id: Option<Vec<u8>>,  // Stored for potential future use and debugging
}

#[derive(Clone, PartialEq, Eq)]
struct SymbolInfo {
    name: String,
    address: u64,
    size: u64,
}

impl PartialOrd for SymbolInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SymbolInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

pub struct Symbolizer {
    main_context: addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
    _main_file_data: &'static [u8],
    symbols: Vec<SymbolInfo>,    // sorted by address
    libraries: HashMap<String, LibraryInfo>,
    memory_maps: Vec<MemoryMapping>,
    file_base_addresses: HashMap<String, u64>,
}

impl Symbolizer {
    pub fn new_from_data(executable_path: &str, memory_maps: &[MemoryMapping], file_base_addresses: &HashMap<String, u64>) -> Result<Self, Box<dyn std::error::Error>> {
        eprintln!("Reading executable file...");
        let file_data = fs::read(executable_path)?;
        
        // Leak the file data to get 'static lifetime
        // This is intentional - we need the data to live for the entire program duration
        let static_file_data: &'static [u8] = Box::leak(file_data.into_boxed_slice());
        
        eprintln!("Parsing object file...");
        let object = object::File::parse(static_file_data)?;
        
        eprintln!("Loading debug sections and creating DWARF info...");
        let main_context = Self::create_context_from_object(&object)?;

        eprintln!("Load symbols from the main executable...");
        let symbols = Self::load_symbols(&object)?;

        eprintln!("Using provided memory maps...");

        Ok(Symbolizer {
            main_context,
            _main_file_data: static_file_data,
            symbols,
            libraries: HashMap::new(),
            memory_maps: memory_maps.to_vec(),
            file_base_addresses: file_base_addresses.clone(),
        })
    }

    fn extract_build_id(object: &object::File) -> Option<Vec<u8>> {
        // Look for the .note.gnu.build-id section
        if let Some(section) = object.section_by_name(".note.gnu.build-id") {
            if let Ok(data) = section.uncompressed_data() {
                // Parse the note structure
                // Note header: namesz (4 bytes), descsz (4 bytes), type (4 bytes)
                // Then name, then description (which contains the build-id)
                if data.len() >= 16 {
                    let namesz = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
                    let descsz = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]) as usize;
                    let note_type = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
                    
                    // GNU build-id note type is 3
                    if note_type == 3 && namesz == 4 {
                        // Skip note header (12 bytes) and name ("GNU\0" = 4 bytes)
                        let build_id_start = 16;
                        if build_id_start + descsz <= data.len() {
                            return Some(data[build_id_start..build_id_start + descsz].to_vec());
                        }
                    }
                }
            }
        }
        None
    }

    fn get_debug_file_path(build_id: &[u8]) -> Option<String> {
        if build_id.len() < 2 {
            return None;
        }
        
        // Convert build-id to hex string
        let hex_string: String = build_id.iter().map(|b| format!("{b:02x}")).collect();
        
        // Split into first two hex digits and the rest
        let (prefix, suffix) = hex_string.split_at(2);
        
        // Construct path: /usr/lib/debug/xy/name.debug
        Some(format!("/usr/lib/debug/.build-id/{prefix}/{suffix}.debug"))
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

    fn find_library_for_address(&self, address: u64) -> Option<&MemoryMapping> {
        self.memory_maps.iter().find(|mapping| {
            address >= mapping.start && address < mapping.end && 
            mapping.permissions.contains('x') && // Executable
            !mapping.pathname.is_empty() &&
            mapping.pathname != "[vdso]" &&
            mapping.pathname != "[vsyscall]"
        })
    }

    fn load_library(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if self.libraries.contains_key(path) {
            return Ok(());
        }

        // Get the base address from our file_base_addresses mapping
        let base_address = self.file_base_addresses.get(path).copied().unwrap_or(0);
        eprintln!("Loading library {path} at file base address 0x{base_address:x}...");
        
        // Try to read the library file
        let file_data = match fs::read(path) {
            Ok(data) => data,
            Err(e) => {
                // If we can't read the library, skip it
                // eprintln!("Could not load library file {path}, error: {e:?}!");
                return Ok(());
            }
        };
        
        let static_file_data: &'static [u8] = Box::leak(file_data.into_boxed_slice());
        
        // Parse the object file
        let object = match object::File::parse(static_file_data) {
            Ok(obj) => obj,
            Err(_) => return Ok(()), // Skip if we can't parse
        };
        
        // Extract build-id from the library
        let build_id = Self::extract_build_id(&object);
        
        let mut loader = None;
        let mut context = None;
        
        // If we have a build-id, try to load debug info from the standard path
        if let Some(ref build_id_bytes) = build_id {
            if let Some(debug_path) = Self::get_debug_file_path(build_id_bytes) {
                eprintln!("Trying to load debug info from: {debug_path}");
                
                // Try to create loader with debug file
                if Path::new(&debug_path).exists() {
                    match addr2line::Loader::new(&debug_path) {
                        Ok(debug_loader) => {
                            eprintln!("Successfully loaded debug info from {debug_path}");
                            loader = Some(debug_loader);
                        }
                        Err(e) => {
                            eprintln!("Failed to load debug info from {debug_path}: {e}");
                        }
                    }
                } else {
                    eprintln!("Debug file does not exist: {debug_path}");
                }
            }
        }
        
        // If we couldn't load debug info from the standard path, fall back to the library itself
        if loader.is_none() {
            eprintln!("Falling back to loading debug info from library itself");
            match Self::create_context_from_object(&object) {
                Ok(ctx) => context = Some(ctx),
                Err(_) => {
                    eprintln!("No debug info available for library {path}");
                }
            }
        }

        let mut lib_info = LibraryInfo {
            loader,
            context,
            _file_data: static_file_data,
            _base_address: base_address,
            symbols: vec![],
            build_id,
        };

        eprintln!("Loading symbols for library {path}...");
        let symbols = Self::load_symbols(&object)?;
        lib_info.symbols = symbols;

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

        let lookup_address = address;

        // Try to find which library this address belongs to
        let mapping_info = self.find_library_for_address(address).map(|m| (m.pathname.clone(), m.start));
        
        if let Some((pathname, _)) = mapping_info {
            if !pathname.is_empty() && !pathname.starts_with('[') {
                // This is a shared library - load it if we haven't already
                if let Err(e) = self.load_library(&pathname) {
                    eprintln!("Failed to load library {pathname}: {e}");
                }
                
                // Try to symbolize using the library
                if let Some(lib_info) = self.libraries.get(&pathname) {
                    // Adjust address relative to library base (file start, not executable segment)
                    if let Some(adr) = self.file_base_addresses.get(&pathname) {
                        let relative_address = address - adr;
                        
                        // Try with loader first if available
                        if let Some(ref loader) = lib_info.loader {
                            if let Some(symbolized) = self.try_symbolize_with_loader(loader, relative_address, address) {
                                return symbolized;
                            }
                        }
                        
                        // Fall back to context if available
                        if let Some(ref context) = lib_info.context {
                            if let Some(symbolized) = self.try_symbolize_with_context(context, relative_address, address) {
                                return symbolized;
                            }
                        }

                        // Fall back to symbol table lookup
                        if let Some(symbol) = find_symbol_for_address(&lib_info.symbols, address) {
                            result.function_name = Some(symbol.name.clone());
                            return result;
                        }
                    } else {
                        eprintln!("Strange, address {address:x} is in mapping of {pathname} for which we do not find a base address, skipping...");
                    }

                }
            }
        }
        
        // Fall back to main executable
        // For main executable, try to find its base address in our mapping
        // Look for a mapping that contains this address but isn't a library
        let main_relative_address = if let Some(main_mapping) = self.find_library_for_address(address) {
            if let Some(&main_exe_base) = self.file_base_addresses.get(&main_mapping.pathname) {
                address - main_exe_base
            } else {
                address
            }
        } else {
            address
        };
        
        if let Some(symbolized) = self.try_symbolize_with_context(&self.main_context, main_relative_address, address) {
            return symbolized;
        }

        // Fall back to symbol table lookup for main executable
        if let Some(symbol) = find_symbol_for_address(&self.symbols, address) {
            result.function_name = Some(symbol.name.clone());
            return result;
        }

        // If still no function name, provide a fallback
        result.function_name = Some(format!("<unknown_{address:x}>"));
        result
    }

    fn try_symbolize_with_loader(&self, loader: &addr2line::Loader, lookup_address: u64, original_address: u64) -> Option<SymbolizedFrame> {
        let mut result = SymbolizedFrame {
            address: original_address,
            function_name: None,
            file_name: None,
            line_number: None,
        };

        // Try to find location information for this address
        match loader.find_location(lookup_address) {
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
                // Error finding location - continue to try symbol lookup
            }
        }

        // Try to find function information for this address using find_frames
        match loader.find_frames(lookup_address) {
            Ok(mut frames) => {
                if let Ok(Some(frame)) = frames.next() {
                    if let Some(function) = frame.function {
                        // Get the raw function name
                        let raw_name = function.raw_name().unwrap_or(std::borrow::Cow::Borrowed("<unknown>"));
                        
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
                }
            }
            Err(_) => {
                // Error finding frames
            }
        }
        
        // Return the result if we found something
        if result.function_name.is_some() || result.file_name.is_some() {
            Some(result)
        } else {
            None
        }
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

fn find_symbol_for_address(symbols: &[SymbolInfo], address: u64) -> Option<&SymbolInfo> {
    // Use binary search to find the symbol that contains this address
    // Since symbols are sorted by address, we need to find the largest address <= target
    match symbols.binary_search_by_key(&address, |s| s.address) {
        Ok(index) => Some(&symbols[index]),
        Err(insert_index) => {
            if insert_index > 0 {
                let candidate = &symbols[insert_index - 1];
                // Check if the address falls within this symbol's range
                if candidate.size > 0 && address < candidate.address + candidate.size {
                    Some(candidate)
                } else if candidate.size == 0 && address >= candidate.address {
                    // For symbols with unknown size, assume they extend to the next symbol
                    if insert_index < symbols.len() {
                        let next_symbol = &symbols[insert_index];
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

