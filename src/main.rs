mod steamnvke;

use std::fs;
use std::io::Write;
use std::path::Path;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use pelite::pe64::{Pe, PeFile, Rva};
use pelite::{Error, FileMap, Result};
use pelite::Error::{Encoding, Null};
use pelite::pe32::headers::SectionHeader;
use ::steamnvke::{find_infix_windows, steam_xor};

#[repr(C)]
#[derive(Copy, Clone)]
struct SteamStub64Var31Header {
    xor_key: u32,
    signature: u32,
    image_base: u64,
    address_of_entry_point: u64,
    bind_section_offset: u32,
    unknown_0000: u32,
    original_entry_point: u64,
    unknown_0001: u32,
    payload_size: u32,
    drmp_dll_offset: u32,
    drmp_dll_size: u32,
    steam_app_id: u32,
    flags: u32,
    bind_section_virtual_size: u32,
    unknown_0002: u32,
    code_section_virtual_address: u64,
    code_section_raw_size: u64,
    aes_key: [u8; 0x20],
    aes_iv: [u8; 0x10],
    code_section_stolen_data: [u8; 0x10],
    encryption_keys: [u32; 0x04],
    unknown_0003: [u32; 0x08],
    get_module_handle_a_rva: u64,
    get_module_handle_w_rva: u64,
    load_library_a_rva: u64,
    load_library_w_rva: u64,
    get_proc_address_rva: u64,
}

unsafe impl bytemuck::Pod for SteamStub64Var31Header {}
unsafe impl bytemuck::Zeroable for SteamStub64Var31Header {}

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

fn get_owner_section<'a>(file: &'a PeFile<'a>, rva: u32) -> Option<&'a SectionHeader> {
    for sect in file.section_headers() {
        let mut size = sect.VirtualSize;
        if size == 0 {
            size = sect.SizeOfRawData;
        }
       if (rva >= sect.VirtualAddress) && (rva < sect.VirtualAddress + size) {
           return Some(sect);
       }
    }
    None
}

// public NativeApi64.ImageSectionHeader64 GetOwnerSection(ulong rva)
// {
// foreach (var s in this.Sections)
// {
// var size = s.VirtualSize;
// if (size == 0)
// size = s.SizeOfRawData;
//
// if ((rva >= s.VirtualAddress) && (rva < s.VirtualAddress + size))
// return s;
// }
//
// return default(NativeApi64.ImageSectionHeader64);
// }

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

    println!("Checking header size");
    let header = &bind[offset+3..offset+7];
    let header = u32::from_le_bytes(header.try_into().unwrap());
    if header == 0xF0 {
        Ok(())
    } else {
        Err(Error::Bounds)
    }
}

fn strip_drm(file: &PeFile, file_data: &[u8]) -> Result<()>  {
    let entry_point = file.nt_headers().OptionalHeader.AddressOfEntryPoint;
    let file_offset = file.rva_to_file_offset(entry_point)?;
    let offset = file_offset - 0xF0;
    let file_data_: &mut [u8] = &mut file_data.to_vec().clone();
    let header_data = file_data_[offset..offset+0xF0].as_mut();
    let mut xor_key = steam_xor(header_data, 0xF0, 0);
    let stub_header: &SteamStub64Var31Header = bytemuck::from_bytes(header_data);
    if stub_header.signature != 0xC0DEC0DF {
        // Implement checking TLS callbacks
        return Err(Encoding)
    }

    // this.File.NtHeaders.OptionalHeader.AddressOfEntryPoint - this.StubHeader.BindSectionOffset
    let payload_addr = file.rva_to_file_offset(file.nt_headers().OptionalHeader.AddressOfEntryPoint - stub_header.bind_section_offset)?;
    let payload_size = (stub_header.payload_size + 0x0F) & 0xFFFFFFF0;
    if payload_size != 0 {
        let file_data: &mut [u8] = &mut file_data.to_vec().clone();
        let payload_end = payload_addr + payload_size as usize;
        let payload = file_data[payload_addr..payload_end].as_mut();
        xor_key = steam_xor(payload, payload_size, xor_key);
    }

    if stub_header.flags & 4 != 4 {
        if let Some(code_section) = get_owner_section(&file, stub_header.code_section_virtual_address as u32) {
            if code_section.SizeOfRawData > 0 {
                let mut code_section_data = vec![0u8; code_section.SizeOfRawData as usize + stub_header.code_section_stolen_data.len()];

                // Copy the stolen data to the beginning of code_section_data
                code_section_data[..stub_header.code_section_stolen_data.len()]
                    .copy_from_slice(&stub_header.code_section_stolen_data);

                // Copy the remaining code section data
                let start_offset = stub_header.code_section_stolen_data.len();
                let file_offset = file.rva_to_file_offset(code_section.VirtualAddress)? as usize;
                code_section_data[start_offset..].copy_from_slice(
                    &file_data[file_offset..file_offset + code_section.SizeOfRawData as usize]
                );

                println!("ok {}", BASE64_STANDARD.encode(code_section_data))
            }
        }
    }


    Ok(())
}


fn file_map<P: AsRef<Path> + ?Sized>(path: &P) -> Result<()> {
    let path = path.as_ref();
    if let Ok(map) = FileMap::open(path) {
        let file = PeFile::from_bytes(&map)?;
        check_is_variant31_x64(&file)?;
        strip_drm(&file, (&map).as_ref())?;
    }
    Ok(())
}

fn main() {
    let path = "/Users/octeep/Downloads/LimbusCompany.exe";
    file_map(path).unwrap()
}