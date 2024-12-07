pub fn find_infix_windows(haystack: &[u8], needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    // Remove spaces and create pattern/mask pairs
    let pattern: Vec<(u8, bool)> = needle
        .split_whitespace() // Split on whitespace
        .filter(|s| !s.is_empty()) // Remove empty strings
        .map(|byte_str| {
            if byte_str == "??" {
                (0, false) // false means this byte should be masked (ignored in comparison)
            } else {
                // Parse as hex and mark as unmasked
                (u8::from_str_radix(byte_str, 16).unwrap(), true)
            }
        })
        .collect();

    if pattern.is_empty() {
        return Some(0);
    }

    haystack.windows(pattern.len()).position(|window| {
        window
            .iter()
            .zip(&pattern)
            .all(|(haystack_byte, (pattern_byte, is_match))| {
                !is_match || haystack_byte == pattern_byte
            })
    })
}

pub fn steam_xor(data: &mut [u8], size: u32, mut key: u32) -> u32 {
    let mut offset = 0u32;

    // Read the first key as the base xor key if we had none given
    if key == 0 {
        offset += 4;
        key = u32::from_le_bytes(data[0..4].try_into().unwrap());
    }

    // Decode the data
    let mut x = offset;
    while x < size {
        let val = u32::from_le_bytes(data[x as usize..(x as usize + 4)].try_into().unwrap());
        let xored = val ^ key;
        data[x as usize..(x as usize + 4)].copy_from_slice(&xored.to_le_bytes());

        key = val;
        x += 4;
    }

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_match() {
        let haystack = &[0x00, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(find_infix_windows(haystack, "11 22"), Some(1));
    }

    #[test]
    fn test_masked_match() {
        let haystack = &[0x00, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(find_infix_windows(haystack, "11 ?? 33"), Some(1));
    }

    #[test]
    fn test_no_match() {
        let haystack = &[0x00, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(find_infix_windows(haystack, "11 22 55"), None);
    }

    #[test]
    fn test_empty_needle() {
        let haystack = &[0x00, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(find_infix_windows(haystack, ""), Some(0));
    }

    #[test]
    fn test_multiple_masks() {
        let haystack = &[0x00, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(find_infix_windows(haystack, "11 ?? ?? 44"), Some(1));
    }

    #[test]
    fn test_steam_xor() {
        let mut text: [u8; 24] = *b"Be myslf no matter what.";
        let body = text.as_mut_slice();
        assert_eq!(steam_xor(body, 16, 0xDEADBEEF), 1953784173);
        assert_eq!(
            hex::encode(body),
            "addb8db33b164c0b591d03464d0f1b54657220776861742e"
        );
    }
}
