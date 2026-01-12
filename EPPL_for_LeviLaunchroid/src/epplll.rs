use clear_cache::clear_cache;
use log::{info, warn};
use region::{protect, Protection};
use std::{fs, ops::Range, sync::OnceLock};

const TARGET_MODULE: &str = "libminecraftpe.so";

struct SignaturePatch {
    search: &'static str,
    replace: &'static str,
    repeat: usize,
}

struct SignatureGroup {
    name: &'static str,
    patches: &'static [SignaturePatch],
}

fn patch_piston_limits_impl(
    groups: &[SignatureGroup],
) -> Result<(), &'static str> {
    for group in groups.iter().filter(|g| !g.patches.is_empty()) {
        match apply_group(group) {
            Ok(()) => {
                info!("Applied piston limit patch via {}", group.name);
                return Ok(());
            }
            Err(err) => {
                warn!("Failed to apply signature group {}: {}", group.name, err);
            }
        }
    }
    Err("No matching piston-limit signature groups found")
}

fn apply_group(group: &SignatureGroup) -> Result<(), &'static str> {
    let mut resolved = Vec::new();

    for patch in group.patches {
        let pattern = SignaturePattern::new(patch.search)?;
        let replacement = parse_replacement(patch.replace)?;
        if replacement.len() != pattern.len() {
            return Err("Replacement length mismatch");
        }

        let mut runs = 0;
        let mut search_from = 0;
        while runs < patch.repeat {
            if let Some(addr) = find_signature(&pattern, search_from) {
                search_from = addr as usize + 1; // move forward
                resolved.push((addr, replacement.clone()));
                runs += 1;
            } else {
                break;
            }
        }
    }

    for (addr, replacement) in resolved {
        unsafe { write_patch(addr, &replacement)?; }
    }

    Ok(())
}

unsafe fn write_patch(addr: *mut u8, bytes: &[PatternByte]) -> Result<(), &'static str> {
    protect(addr, bytes.len(), Protection::READ_WRITE_EXECUTE)
        .map_err(|_| "Memory protection change failed")?;

    for (i, pb) in bytes.iter().enumerate() {
        let dst = addr.add(i);
        let orig = *dst;
        let new_val = (orig & !pb.mask) | (pb.value & pb.mask);
        std::ptr::write(dst, new_val);
    }
    clear_cache(addr, addr.add(bytes.len()));

    protect(addr, bytes.len(), Protection::READ_EXECUTE).ok();
    Ok(())
}

fn find_signature(pattern: &SignaturePattern, start_addr: usize) -> Option<*mut u8> {
    let ranges = module_ranges().ok()?;

    for range in ranges {
        // Skip ranges before continue point
        if start_addr >= range.end {
            continue;
        }

        let begin = if start_addr > range.start {
            start_addr
        } else {
            range.start
        };

        if let Some(addr) = unsafe {
            scan_range(begin..range.end, pattern)
        } {
            return Some(addr);
        }
    }
    None
}

unsafe fn scan_range(range: Range<usize>, pattern: &SignaturePattern) -> Option<*mut u8> {
    let start = range.start as *const u8;
    let len = range.end.saturating_sub(range.start);

    if len < pattern.len() {
        return None;
    }

    for offset in 0..=len - pattern.len() {
        let addr = start.add(offset);
        if pattern.matches(addr) {
            return Some(addr as *mut u8);
        }
    }
    None
}

fn module_ranges() -> Result<&'static [Range<usize>], &'static str> {
    static CACHE: OnceLock<Vec<Range<usize>>> = OnceLock::new();
    CACHE
        .get_or_try_init(load_module_ranges)
        .map(|ranges| -> &'static [Range<usize>] { ranges.as_slice() })
}

fn load_module_ranges() -> Result<Vec<Range<usize>>, &'static str> {
    let maps = fs::read_to_string("/proc/self/maps").map_err(|_| "Cannot read /proc/self/maps")?;

    let mut ranges = Vec::new();
    for line in maps.lines() {
        if !line.contains(TARGET_MODULE) {
            continue;
        }

        let mut parts = line.split_whitespace();
        let range_part = parts.next().ok_or("Malformed maps entry")?;
        let perms = parts.next().ok_or("Missing permissions in maps entry")?;

        if !perms.starts_with('r') {
            continue;
        }

        let mut bounds = range_part.split('-');
        let start = usize::from_str_radix(bounds.next().ok_or("Missing start addr")?, 16)
            .map_err(|_| "Invalid start addr")?;
        let end = usize::from_str_radix(bounds.next().ok_or("Missing end addr")?, 16)
            .map_err(|_| "Invalid end addr")?;

        if end > start {
            ranges.push(start..end);
        }
    }

    if ranges.is_empty() {
        return Err("Target module not found in maps");
    }

    ranges.sort_by_key(|r| r.start);
    Ok(ranges)
}

#[derive(Clone)]
struct SignaturePattern {
    bytes: Vec<PatternByte>,
}

impl SignaturePattern {
    fn new(signature: &str) -> Result<Self, &'static str> {
        let mut bytes = Vec::new();
        for token in signature.split_whitespace() {
            if token.is_empty() {
                continue;
            }
            bytes.push(PatternByte::from_token(token)?);
        }
        if bytes.is_empty() {
            return Err("Signature is empty");
        }
        Ok(Self { bytes })
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    unsafe fn matches(&self, addr: *const u8) -> bool {
        for (offset, pattern_byte) in self.bytes.iter().enumerate() {
            let value = *addr.add(offset);
            if !pattern_byte.matches(value) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Copy)]
struct PatternByte {
    value: u8,
    mask: u8,
}

impl PatternByte {
    fn from_token(token: &str) -> Result<Self, &'static str> {
        if token.len() != 2 {
            return Err("Signature tokens must be exactly two characters");
        }
        let mut chars = token.chars();
        let high = parse_nibble(chars.next().unwrap())?;
        let low = parse_nibble(chars.next().unwrap())?;
        Ok(Self {
            value: (high.value << 4) | low.value,
            mask: (high.mask << 4) | low.mask,
        })
    }

    fn matches(&self, byte: u8) -> bool {
        (byte & self.mask) == (self.value & self.mask)
    }
}

struct Nibble {
    value: u8,
    mask: u8,
}

fn parse_nibble(ch: char) -> Result<Nibble, &'static str> {
    if ch == '?' {
        return Ok(Nibble { value: 0, mask: 0 });
    }
    ch.to_digit(16)
        .map(|digit| Nibble {
            value: digit as u8,
            mask: 0xF,
        })
        .ok_or("Invalid hex nibble")
}

fn parse_replacement(bytes: &str) -> Result<Vec<PatternByte>, &'static str> {
    let mut output = Vec::new();
    for token in bytes.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        output.push(PatternByte::from_token(token)?);
    }
    if output.is_empty() {
        return Err("Replacement sequence is empty");
    }
    Ok(output)
}

// all four architectures

#[cfg(target_arch = "aarch64")] // arm64-v8a
pub fn patch_piston_limits() -> Result<(), &'static str> {
    const SIGNATURE_GROUPS: &[SignatureGroup] = &[
        SignatureGroup {
            name: "piston-limit-primary",
            patches: &[
                SignaturePatch {
                    search: "09 9B 1F 31 00 F1 ?9 0? 00 54",
                    replace: "09 9B 1F FD 3F B1 ?9 0? 00 54",
                    repeat: 1,
                },
                SignaturePatch {
                    search: "09 9B 1F 35 00 F1 ?? 27 9F 1A",
                    replace: "09 9B 1F FD 3F B1 ?? 27 9F 1A",
                    repeat: 2,
                },
            ],
        },
        SignatureGroup { name: "piston-limit-fallback", patches: &[] },
    ];
    patch_piston_limits_impl(SIGNATURE_GROUPS)
}

#[cfg(target_arch = "arm")] // armeabi-v7a
pub fn patch_piston_limits() -> Result<(), &'static str> {
    const SIGNATURE_GROUPS: &[SignatureGroup] = &[
        SignatureGroup {
            name: "piston-limit-primary",
            patches: &[
                SignaturePatch {
                    search: "4A F6 AB 2? CA F6 AA 2? ?? ?? ?? ?? 0D 2?",
                    replace: "4A F6 AB 2? CA F6 AA 2? ?? ?? ?? ?? 01 20",
                    repeat: 1,
                },
                SignaturePatch {
                    search: "4A F6 AB 2? CA F6 AA 2? ?? ?? ?? ?? ?? ?? 0D 2?",
                    replace: "4A F6 AB 2? CA F6 AA 2? ?? ?? ?? ?? ?? ?? 01 20",
                    repeat: 1,
                },
                SignaturePatch { //for 0.15.0.1 ONLY edit(after-testing)-works!
                    search: "CA F6 AA 2? 80 1? ?? ?? ?? ?? 0D 2?",
                    replace: "CA F6 AA 2? 80 1? ?? ?? ?? ?? 01 20",
                    repeat: 1,
                },
            ],
        },
        SignatureGroup { name: "piston-limit-fallback", patches: &[] },
    ];
    patch_piston_limits_impl(SIGNATURE_GROUPS)
}

#[cfg(target_arch = "x86")] //x86
pub fn patch_piston_limits() -> Result<(), &'static str> {
    const SIGNATURE_GROUPS: &[SignatureGroup] = &[
        SignatureGroup {
            name: "piston-limit-primary",
            patches: &[
                SignaturePatch {
                    search: "AB AA AA AA 83 F? 0D",
                    replace: "AB AA AA AA 83 F? FF",
                    repeat: 2,
                },
            ],
        },
        SignatureGroup { name: "piston-limit-fallback", patches: &[] },
    ];
    patch_piston_limits_impl(SIGNATURE_GROUPS)
}

#[cfg(target_arch = "x86_64")] //x86_64
pub fn patch_piston_limits() -> Result<(), &'static str> {
    const SIGNATURE_GROUPS: &[SignatureGroup] = &[
        SignatureGroup {
            name: "piston-limit-primary",
            patches: &[
                SignaturePatch {
                    search: "AB AA AA AA AA AA AA AA 48 ?? ?? ?? ?? ?3 ?? 0D",
                    replace: "AB AA AA AA AA AA AA AA 48 ?? ?? ?? ?? ?3 ?? FF",
                    repeat: 2,
                },
            ],
        },
        SignatureGroup { name: "piston-limit-fallback", patches: &[] },
    ];
    patch_piston_limits_impl(SIGNATURE_GROUPS)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86", target_arch = "x86_64")))]
pub fn patch_piston_limits() -> Result<(), &'static str> {
    Err("Unsupported architecture for piston-limit patch")
}