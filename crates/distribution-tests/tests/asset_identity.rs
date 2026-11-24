//! Boundaries for manifest member and digest admission, shared by native tests and Verus.
#![allow(unexpected_cfgs)]
#[cfg(verus_keep_ghost)]
#[path = "../../distribution/src/asset_identity.rs"]
mod policy;
#[cfg(not(verus_keep_ghost))]
use chrono_distribution::asset_identity as policy;
#[cfg(not(verus_keep_ghost))]
use verus_builtin_macros::verus;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::vpanic as panic;

verus! {
fn expect(ok: bool)
    requires ok,
{
    if !ok { panic!(); }
}

#[cfg_attr(not(verus_keep_ghost), test)]
fn manifest_leaf_names_and_path_boundaries() {
    expect(policy::valid_name(&[0x41u8, 0x2du8, 0x30u8, 0x5fu8, 0x7au8, 0x2eu8, 0x74u8]));
    expect(policy::valid_name(&[0x2eu8, 0x2eu8, 0x2eu8]));
    expect(!policy::valid_name(&[]));
    expect(!policy::valid_name(&[0x2eu8]));
    expect(!policy::valid_name(&[0x2eu8, 0x2eu8]));
    expect(!policy::valid_name(&[0x61u8, 0x2fu8, 0x62u8]));
    expect(!policy::valid_name(&[255u8]));
}

#[cfg_attr(not(verus_keep_ghost), test)]
fn object_and_asset_hashes_are_exact_lowercase_hex() {
    let digest = [97u8; 64];
    let commit = [48u8; 40];
    expect(policy::valid_hex(&commit, 40));
    expect(!policy::valid_hex(&commit, 64));
    expect(policy::valid_asset_identity(&digest, 1));
    expect(!policy::valid_asset_identity(&digest, 0));
    let uppercase = [65u8; 64];
    let outside_hex = [103u8; 64];
    proof { assert(!policy::hex_digit(uppercase[0])); assert(!policy::hex_digit(outside_hex[0])); }
    expect(!policy::valid_asset_identity(&uppercase, 1));
    expect(!policy::valid_asset_identity(&outside_hex, 1));
}

struct Steps {
    items: Vec<policy::Observation<u8>>,
}

impl policy::MemberSource<u8> for Steps {
    closed spec fn pending(&self) -> Seq<policy::Observation<u8>> { self.items@ }

    fn next(&mut self) -> (out: Option<policy::Observation<u8>>) {
        if self.items.is_empty() { return None; }
        let first = self.items.remove(0);
        proof { assert(self.items@ =~= old(self).items@.drop_first()); }
        Some(first)
    }
}

#[cfg_attr(not(verus_keep_ghost), test)]
fn text_precedes_observation_and_first_failure_wins() {
    use policy::MemberError;
    use policy::Observation;
    let mut src = Steps { items: Vec::new() };
    src.items.push(Observation::Symlink);
    src.items.push(Observation::Io(20));
    let bad = policy::check_member(&[65, 92], &mut src);
    expect(matches!(bad, Err(MemberError::InvalidPath)));
    expect(src.items.len() == 2);
    proof { reveal_with_fuel(policy::first_error, 4); }
    let link = policy::check_member(&[65], &mut src);
    expect(matches!(link, Err(MemberError::Symlink)));

    let mut src = Steps { items: Vec::new() };
    src.items.push(Observation::Present);
    src.items.push(Observation::Missing);
    let accepted = policy::check_member(&[65, 47, 66], &mut src);
    expect(accepted.is_ok());

    let mut src = Steps { items: Vec::new() };
    src.items.push(Observation::Io(20));
    src.items.push(Observation::InvalidComponent);
    let io = policy::check_member(&[65], &mut src);
    expect(matches!(io, Err(MemberError::Io(20))));
}
}
