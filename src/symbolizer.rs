use std::path::Path;

use crate::SymbolizedFrame;

pub struct Symbolizer {
    loader: addr2line::Loader,
}

impl Symbolizer {
    pub fn new(executable_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Create loader with the executable path
        let loader = addr2line::Loader::new(Path::new(executable_path))?;
        
        Ok(Symbolizer {
            loader,
        })
    }
    
    pub fn symbolize(&self, address: u64) -> SymbolizedFrame {
        let mut result = SymbolizedFrame {
            address,
            function_name: None,
            file_name: None,
            line_number: None,
        };
        
        // Try to find frames (handles inlined functions)
        if let Ok(mut frames) = self.loader.find_frames(address) {
            // Get the outermost (non-inlined) frame first
            if let Ok(Some(frame)) = frames.next() {
                // Get function name
                if let Some(function) = frame.function {
                    if let Ok(name) = function.demangle() {
                        result.function_name = Some(name.to_string());
                    } else if let Ok(raw_name) = function.raw_name() {
                        result.function_name = Some(raw_name.to_string());
                    }
                }
                
                // Get location information
                if let Some(location) = frame.location {
                    if let Some(file) = location.file {
                        result.file_name = Some(file.to_string());
                    }
                    result.line_number = location.line;
                }
            }
        }
        
        // Fallback if frames lookup didn't work
        if result.function_name.is_none() {
            if let Ok(Some(location)) = self.loader.find_location(address) {
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