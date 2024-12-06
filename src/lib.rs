mod steamnvke;

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

    haystack
        .windows(pattern.len())
        .position(|window| {
            window.iter().zip(&pattern).all(|(haystack_byte, (pattern_byte, is_match))| {
                !is_match || haystack_byte == pattern_byte
            })
        })
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
}