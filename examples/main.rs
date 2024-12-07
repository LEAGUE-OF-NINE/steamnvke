use std::{env, fs};
use pelite::FileMap;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = match args.get(1) {
        None => panic!("No path supplied in arguments"),
        Some(p) => p,
    };

    let map = FileMap::open(path).unwrap();
    let new_file = steamnvke::drm::strip_drm_from_exe(map.as_ref()).unwrap();
    println!("Written {} bytes", new_file.len());
    fs::write("unpacked.exe", new_file).unwrap();
}
