use std::fs;
use pelite::FileMap;

fn main() {
    let path = "/Users/octeep/Downloads/LimbusCompany.exe";
    if let Ok(map) = FileMap::open(path) {
        let new_file = steamnvke::drm::strip_drm_from_exe(map.as_ref()).unwrap();
        println!("Written {} bytes", new_file.len());
        fs::write("unpacked.exe", new_file).unwrap();
    }
}
