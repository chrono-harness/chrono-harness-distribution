//! Admission of release member names and the lowercase hexadecimal identities used by the manifest.
#![allow(unexpected_cfgs)]
#[cfg(not(verus_keep_ghost))]
use verus_builtin_macros::verus;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

verus! {
pub open spec fn hex_digit(b: u8) -> bool {
    48 <= b <= 57 || 97 <= b <= 102
}

pub open spec fn name_byte(b: u8) -> bool {
    48 <= b <= 57 || 65 <= b <= 90 || 97 <= b <= 122 || b == 46 || b == 45 || b == 95
}

pub open spec fn release_name(s: Seq<u8>) -> bool {
    s.len() > 0 && !(s.len() == 1 && s[0] == 46)
        && !(s.len() == 2 && s[0] == 46 && s[1] == 46)
        && forall|i: int| 0 <= i < s.len() ==> name_byte(#[trigger] s[i])
}

pub fn valid_name(s: &[u8]) -> (valid: bool)
    ensures valid == release_name(s@),
{
    if s.is_empty() || (s.len() == 1 && s[0] == 46)
        || (s.len() == 2 && s[0] == 46 && s[1] == 46) {
        return false;
    }
    let mut i = 0;
    while i < s.len()
        invariant
            i <= s.len(),
            forall|j: int| 0 <= j < i ==> name_byte(#[trigger] s[j]),
        decreases s.len() - i,
    {
        let b = s[i];
        if !((48 <= b && b <= 57) || (65 <= b && b <= 90) || (97 <= b && b <= 122)
            || b == 46 || b == 45 || b == 95) { return false; }
        i += 1;
    }
    true
}

pub fn valid_hex(s: &[u8], length: usize) -> (valid: bool)
    ensures valid == (s@.len() == length
        && forall|i: int| 0 <= i < s.len() ==> hex_digit(#[trigger] s[i])),
{
    if s.len() != length { return false; }
    let mut i = 0;
    while i < s.len()
        invariant
            i <= s.len(),
            forall|j: int| 0 <= j < i ==> hex_digit(#[trigger] s[j]),
        decreases s.len() - i,
    {
        let b = s[i];
        if !((48 <= b && b <= 57) || (97 <= b && b <= 102)) { return false; }
        i += 1;
    }
    true
}

pub fn valid_asset_identity(digest: &[u8], size: u64) -> (valid: bool)
    ensures valid == (size > 0 && digest.len() == 64
        && forall|i: int| 0 <= i < digest.len() ==> hex_digit(#[trigger] digest[i])),
{
    size > 0 && valid_hex(digest, 64)
}
}
