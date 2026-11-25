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

/// Independent consequences for a selected name missing twice, two distinct
/// unknown names, and a single available member with its exact lock destination.
proof fn selection_first_failure_and_exact_destination(
    first: String, second: String, available: Set<Seq<char>>,
    destinations: Map<Seq<char>, Seq<char>>, out: Result<(), policy::SelectionError>,
)
    requires first@ != second@, !available.contains(first@), !available.contains(second@),
    ensures
        policy::selection_outcome(seq![first, second, second], available, destinations, out)
            ==> out == Err::<(), _>(policy::SelectionError::Duplicate),
        policy::selection_outcome(seq![first, second], available, destinations, out)
            ==> out == Err::<(), _>(policy::SelectionError::Unknown(0)),
        policy::selection_outcome(seq![first], available.insert(first@), destinations, out)
            ==> out.is_ok()
            && destinations.dom() =~= set![first@]
            && destinations[first@] == ".chrono-harness/bin/"@ + first@,
{
    let repeated = seq![first, second, second];
    assert(repeated[1]@ == repeated[2]@);
    let distinct = seq![first, second];
    assert forall|a:int, b:int| 0 <= a < b < 2 implies distinct[a]@ != distinct[b]@ by {
        assert(a == 0 && b == 1);
    }
    let singleton = seq![first];
    if policy::selection_outcome(singleton, available.insert(first@), destinations, out) {
        assert(policy::different_names(singleton, 1));
        match out {
            Err(policy::SelectionError::Duplicate) => { assert(!policy::different_names(singleton,singleton.len() as int)); assert(false); },
            Err(policy::SelectionError::Unknown(i)) => {
                assert(i == 0 && singleton[0]@ == first@);
                assert(!available.insert(first@).contains(singleton[i as int]@));
                assert(available.insert(first@).contains(first@));
                assert(false);
            },
            Ok(()) => {},
        }
        assert(out.is_ok());
        assert(singleton[0]@ == first@);
        assert(destinations[first@] == ".chrono-harness/bin/"@ + first@);
        assert forall|k:Seq<char>| destinations.dom().contains(k) <==> k == first@ by {
            if destinations.dom().contains(k) {
                let i = choose|i: int| 0 <= i < 1 && (#[trigger] singleton[i])@ == k;
                assert(i == 0);
            } else if k == first@ { assert(singleton[0]@ == k); }
        }
        assert(destinations.dom() =~= set![first@]);
    }
}

#[cfg_attr(not(verus_keep_ghost), test)]
fn launcher_options_preserve_modes_and_first_failure() {
    use policy::{launcher_action, LauncherAction::*, LauncherOption, LauncherValue::*};
    expect(matches!(launcher_action(false, LauncherOption::Host, true, Missing), MissingHost));
    expect(matches!(launcher_action(true, LauncherOption::Host, true, Name), DuplicateHost));
    expect(matches!(launcher_action(false, LauncherOption::Host, false, Other), SetHost));
    expect(matches!(launcher_action(false, LauncherOption::Tool, false, Missing), InstallTool));
    expect(matches!(launcher_action(true, LauncherOption::Tool, false, Missing), MissingTool));
    expect(matches!(launcher_action(true, LauncherOption::Tool, false, Other), InvalidTool));
    expect(matches!(launcher_action(true, LauncherOption::Tool, false, Name), AddTool));
    expect(matches!(launcher_action(false, LauncherOption::Replace, true, Missing), InstallReplace));
    expect(matches!(launcher_action(true, LauncherOption::Replace, true, Missing), DuplicateReplace));
    expect(matches!(launcher_action(true, LauncherOption::Replace, false, Missing), SetReplace));
    expect(matches!(launcher_action(true, LauncherOption::Unknown, false, Name), Unknown));
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
#[cfg_attr(not(verus_keep_ghost), test)]
fn install_marker_and_expiry_boundaries() {
    expect(policy::same_install_file(true, 3, 5, true, 3, 5));
    expect(!policy::same_install_file(true, 3, 5, true, 3, 6));
    expect(!policy::same_install_file(true, 3, 5, true, 6, 5));
    expect(!policy::same_install_file(false, 3, 5, true, 3, 5));
    expect(!policy::same_install_file(true, 3, 5, false, 3, 5));
    expect(!policy::install_stage_expired(5, None));
    expect(!policy::install_stage_expired(5, Some(4)));
    expect(policy::install_stage_expired(5, Some(5)));
}

#[cfg_attr(not(verus_keep_ghost), test)]
fn measured_asset_requires_both_digest_and_size() {
    expect(policy::matches_observed_asset("0123", 10, "0123", 10));
    expect(!policy::matches_observed_asset("0123", 10, "0124", 10));
    expect(!policy::matches_observed_asset("0123", 10, "0123", 11));
    expect(!policy::matches_observed_asset("0123", 10, "0124", 11));
}

}
