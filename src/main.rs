mod steamnvke;

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;
use aes::cipher::KeyInit;
use aes::cipher::generic_array::GenericArray;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bytemuck::bytes_of;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::cipher::block_padding::NoPadding;
use pelite::pe64::{Pe, PeFile, PeObject, Rva};
use pelite::{Error, FileMap, Result};
use pelite::Error::{Encoding, Insanity, Null};
use pelite::image::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};
use pelite::pe32::headers::SectionHeader;
use pelite::pe64::image::IMAGE_NT_HEADERS;
use pelite::util::AlignTo;
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

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct WrappedImageDosHeader(IMAGE_DOS_HEADER);

unsafe impl bytemuck::Pod for WrappedImageDosHeader {}
unsafe impl bytemuck::Zeroable for WrappedImageDosHeader {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct WrappedImageNtHeader(IMAGE_NT_HEADERS);

unsafe impl bytemuck::Pod for WrappedImageNtHeader {}
unsafe impl bytemuck::Zeroable for WrappedImageNtHeader {}


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

fn get_owner_section<'a>(file: &'a PeFile<'a>, rva: u32) -> Option<(usize, &'a SectionHeader)> {
    for (i, sect) in file.section_headers().iter().enumerate() {
        let mut size = sect.VirtualSize;
        if size == 0 {
            size = sect.SizeOfRawData;
        }
       if (rva >= sect.VirtualAddress) && (rva < sect.VirtualAddress + size) {
           return Some((i, sect));
       }
    }
    None
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

    println!("Checking header size");
    let header = &bind[offset+3..offset+7];
    let header = u32::from_le_bytes(header.try_into().unwrap());
    if header == 0xF0 {
        Ok(())
    } else {
        Err(Error::Bounds)
    }
}

fn reconstruct_file(file: &PeFile) -> Vec<u8> {
    let (sizeof_headers, sizeof_image, section_alignment) = {
        let optional_header = file.optional_header();
        (optional_header.SizeOfHeaders, optional_header.SizeOfImage, optional_header.SectionAlignment)
    };

    println!("Size of headers {}", sizeof_headers);

    // Zero fill the underlying image
    let mut vec = vec![0u8; sizeof_image as usize];

    // Start by copying the headers
    let image = file.image();
    unsafe {
        // Validated by constructor
        let dest_headers = vec.get_unchecked_mut(..sizeof_headers as usize);
        let src_headers = image.get_unchecked(..sizeof_headers as usize);
        dest_headers.copy_from_slice(src_headers);
    }

    // Copy the section file data
    for section in file.section_headers() {
        let dest = vec.get_mut(section.VirtualAddress as usize..u32::wrapping_add(section.VirtualAddress, section.VirtualSize).align_to(section_alignment) as usize);
        let src = image.get(section.PointerToRawData as usize..u32::wrapping_add(section.PointerToRawData, section.SizeOfRawData) as usize);
        // Skip invalid sections...
        if let (Some(dest), Some(src)) = (dest, src) {
            dest[..src.len()].copy_from_slice(src);
        }
    }

    vec
}

fn strip_drm(file: &PeFile, file_data: &[u8]) -> Result<Vec<u8>>  {
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

    let payload_addr = file.rva_to_file_offset(file.nt_headers().OptionalHeader.AddressOfEntryPoint - stub_header.bind_section_offset)?;
    let payload_size = (stub_header.payload_size + 0x0F) & 0xFFFFFFF0;
    if payload_size != 0 {
        let file_data: &mut [u8] = &mut file_data.to_vec().clone();
        let payload_end = payload_addr + payload_size as usize;
        let payload = file_data[payload_addr..payload_end].as_mut();
        xor_key = steam_xor(payload, payload_size, xor_key);
    }

    let mut decrypted_code_section: Option<(usize, Vec<u8>)> = None;

    // Decrypt code data
    if stub_header.flags & 4 != 4 {
        if let Some((code_section_index, code_section)) = get_owner_section(&file, stub_header.code_section_virtual_address as u32) {
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

                let mut original_iv = stub_header.aes_iv.clone();
                let iv = original_iv.as_mut_slice();
                type Aes256EcbDec = aes::Aes256;
                let cipher = Aes256EcbDec::new(
                    GenericArray::from_slice(&stub_header.aes_key),
                );
                cipher.decrypt_padded_mut::<NoPadding>(&mut *iv).unwrap();

                type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
                let cipher = Aes256CbcDec::new(
                    GenericArray::from_slice(&stub_header.aes_key),
                    GenericArray::from_slice(&iv),
                );

                let plain_code_section = cipher.decrypt_padded_mut::<NoPadding>(code_section_data.as_mut_slice()).unwrap();
                decrypted_code_section = Some((code_section_index, plain_code_section.to_vec()));
            }
        }
    }

    let mut c: Cursor<Vec<u8>> = Cursor::new(Vec::new());

    // DOS Header
    let dos_header = WrappedImageDosHeader { 0: *file.dos_header() };
    let dos_header_bytes = bytes_of(&dos_header);
    c.write_all(dos_header_bytes).unwrap();

    // DOS Stub Data
    if file.dos_header().e_lfanew > dos_header_bytes.len() as u32 {
        let dos_stub_size = file.dos_header().e_lfanew as usize - dos_header_bytes.len();
        let dos_stub: Vec<u8> = vec![0; dos_stub_size];
        c.write_all(&*dos_stub).unwrap();
    }

    // NT Header
    let mut nt_header = *file.nt_headers();
    nt_header.OptionalHeader.AddressOfEntryPoint = stub_header.original_entry_point as u32;
    nt_header.OptionalHeader.CheckSum = 0;
    c.write_all(bytes_of(&WrappedImageNtHeader{ 0: nt_header })).unwrap();

    // Sections
    for (i, sect) in file.section_headers().iter().enumerate() {
        let sect_data = file.get_section_bytes(sect)?;
        c.write_all(dataview::bytes(sect)).unwrap();
        let sect_offset = c.position();
        c.set_position(sect.PointerToRawData as u64);
        match decrypted_code_section {
            Some((code_sect_index, ref code_data)) if i == code_sect_index => c.write_all(&code_data).unwrap(),
            _ => c.write_all(sect_data).unwrap(),
        }
        c.set_position(sect_offset);
    }

    // TODO: Overlay data

    Ok(c.into_inner())
}


fn file_map<P: AsRef<Path> + ?Sized>(path: &P) -> Result<()> {
    let path = path.as_ref();
    if let Ok(map) = FileMap::open(path) {
        let file = PeFile::from_bytes(&map)?;
        reconstruct_file(&file);
        check_is_variant31_x64(&file)?;
        let new_file = strip_drm(&file, (&map).as_ref())?;
        println!("Written {} bytes", new_file.len());
        fs::write("unpacked.exe", new_file).unwrap();
    }
    Ok(())
}

fn main() {
    let path = "/Users/octeep/Downloads/LimbusCompany.exe";
    file_map(path).unwrap()
}