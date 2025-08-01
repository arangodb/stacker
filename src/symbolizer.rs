use std::borrow::Cow;
use std::fs;

use object::{Object, ObjectSection};

use crate::SymbolizedFrame;

pub struct Symbolizer {
    context: addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
    _file_data: &'static [u8],
}

impl Symbolizer {
    pub fn new(executable_path: &str, _pid: i32) -> Result<Self, Box<dyn std::error::Error>> {
        // Read the executable file
        let file_data = fs::read(executable_path)?;
        
        // Leak the file data to get 'static lifetime
        // This is intentional - we need the data to live for the entire program duration
        let static_file_data: &'static [u8] = Box::leak(file_data.into_boxed_slice());
        
        // Parse the object file
        let object = object::File::parse(static_file_data)?;
        
        // Load debug sections and create DWARF info
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
        
        // Create the addr2line context
        let context = addr2line::Context::from_dwarf(dwarf)?;

        Ok(Symbolizer {
            context,
            _file_data: static_file_data,
        })
    }

    pub fn symbolize(&self, address: u64) -> SymbolizedFrame {
        let mut result = SymbolizedFrame {
            address,
            function_name: None,
            file_name: None,
            line_number: None,
        };

        // Try to find location information for this address
        match self.context.find_location(address) {
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
            Err(e) => {
                eprintln!("Error finding location for address 0x{address:x}: {e}");
            }
        }

        // Try to find function information for this address
        // Use the frames API correctly
        let frame_iter = self.context.find_frames(address);
        loop {
            match frame_iter {
                addr2line::LookupResult::Output(Ok(mut frames)) => {
                    if let Ok(Some(frame)) = frames.next() {
                        if let Some(function) = frame.function {
                            // Get the raw function name
                            let raw_name = function.raw_name().unwrap_or(Cow::Borrowed("<unknown>"));
                            
                            // Try to demangle the name
                            let demangled_name = function.demangle().unwrap_or(raw_name);
                            result.function_name = Some(demangled_name.to_string());
                        }
                    }
                    break;
                },
                addr2line::LookupResult::Output(Err(_e)) => {
                    // Error occurred, break out
                    break;
                },
                addr2line::LookupResult::Load { load: _, continuation: _ } => {
                    // This is a lazy loading scenario - we need to call the continuation
                    // For simplicity, we'll just skip this case and use fallback
                    break;
                }
            }
        }

        // If still no function name, provide a fallback
        if result.function_name.is_none() {
            result.function_name = Some(format!("<unknown_{address:x}>"));
        }

        result
    }
}
