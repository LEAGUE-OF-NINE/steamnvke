mod steamnvke;

use std::fs;
use std::io::Write;
use std::path::Path;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use pelite::pe64::{Pe, PeFile};
use pelite::{Error, FileMap, Result};
use ::steamnvke::find_infix_windows;

fn bind_section<'a>(file: &'a PeFile<'a>) -> Result<&'a [u8]> {
    for sect in file.section_headers() {
        let name: String = String::from_utf8_lossy(&sect.Name)
            .chars()
            .filter(|&c| c != '\0')
            .collect();
        if name == ".bind" {
            return file.get_section_bytes(sect);
        }
    }

    Err(Error::Null)
}

fn check_is_variant31_x64(file: &PeFile) -> Result<()>  {
    let bind = bind_section(&file)?;

    println!("Checking known v3.x signature");
    match find_infix_windows(bind, "E8 00 00 00 00 50 53 51 52 56 57 55 41 50") {
        None => return Err(Error::Encoding),
        Some(_) => {}
    }

    println!("Checking for offset");
    let offset =
        find_infix_windows(bind, "48 8D 91 ?? ?? ?? ?? 48")
            .or(find_infix_windows(bind, "48 8D 91 ?? ?? ?? ?? 41"))
            .or(find_infix_windows(bind, "48 C7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 48").map(|x| x+5))
            .ok_or(Error::Encoding)?;

    print!("Checking header size");
    let header = &bind[offset+3..offset+7];
    let header = u32::from_le_bytes(header.try_into().unwrap());
    if header == 0xF0 {
        Ok(())
    } else {
        Err(Error::Bounds)
    }
}

fn file_map<P: AsRef<Path> + ?Sized>(path: &P) -> Result<()> {
    let path = path.as_ref();
    if let Ok(map) = FileMap::open(path) {
        let file = PeFile::from_bytes(&map)?;
        check_is_variant31_x64(&file)?;
    }
    Ok(())
}

fn main() {
    let path = "/Users/octeep/Downloads/LimbusCompany.exe";
    file_map(path).unwrap()
}