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
fn deployed_host_inputs() -> (&'static str, &'static str, &'static str) {
    (include_str!("../../../.github/roadmap.cjs"),
     include_str!("../../../.github/workflows/issue-roadmap.yml"),
     include_str!("../../../.chrono-harness/install-tools.sh"))
}

fn matches_host_template(roadmap: &String, workflow: &String, installer: &String) -> (matched: bool)
    ensures matched == (roadmap@ == "5824ea576bd25a792c76e976dc2dcec1c7eb684f6a3a9de9919220a546b61cf9"@ && workflow@ == "47fe8e13ad7ade04ac0882ea76eda196256b71b24f9d7ebd0a1b3322309bb9eb"@ && installer@ == "463052d115cab6d117f83b7546ee3c9481f42ab210c4347833668f84eb6d1941"@),
{
    roadmap.eq(&"5824ea576bd25a792c76e976dc2dcec1c7eb684f6a3a9de9919220a546b61cf9".to_string()) && workflow.eq(&"47fe8e13ad7ade04ac0882ea76eda196256b71b24f9d7ebd0a1b3322309bb9eb".to_string())
        && installer.eq(&"463052d115cab6d117f83b7546ee3c9481f42ab210c4347833668f84eb6d1941".to_string())
}

fn expect(ok: bool)
    requires ok,
{
    if !ok { panic!(); }
}

#[cfg_attr(not(verus_keep_ghost), test)]
fn all_platforms_must_publish_the_same_member_names() {
    let a = "a".to_string();
    let b = "b".to_string();
    let other_b = "b".to_string();
    let c = "c".to_string();
    proof {
        reveal_strlit("b");
        reveal_strlit("c");
        assert(b@[0] != c@[0]);
    }
    expect(policy::same_platform_members(&[&a, &b], &[&a, &other_b]));
    expect(!policy::same_platform_members(&[&a, &b], &[&a]));
    expect(!policy::same_platform_members(&[&a], &[&a, &b]));
    expect(!policy::same_platform_members(&[&a, &b], &[&a, &c]));
}

/// For any real adapter, distinguish a failure during rename from an earlier
/// write failure and require the exact identities in a successful receipt.
fn publication_results_follow_the_last_completed_step<P: policy::Publication<u8, u8>>(
    output: &mut P,
)
{
    let ghost start = output.steps().len() as int;
    let result = policy::publish_assembly(output);
    proof {
        let steps = output.steps();
        if steps.len() == start + 1 && steps[start] == policy::PublicationStep::<u8,u8>::Manifest(Err(7u8)) {
            assert(result == Err::<(u8,u8),u8>(7u8));
        }
        if steps.len() == start + 2 && steps[start + 1] == policy::PublicationStep::<u8,u8>::Launcher(Err(13u8)) {
            assert(steps[start] matches policy::PublicationStep::Manifest(Ok(_)));
            assert(result == Err::<(u8,u8),u8>(13u8));
        }
        if steps.len() == start + 3 {
            assert(steps[start] matches policy::PublicationStep::Manifest(Ok(_)));
            assert(steps[start + 1] matches policy::PublicationStep::Launcher(Ok(_)));
            if steps[start + 2] == policy::PublicationStep::<u8,u8>::Rename(Err(23u8)) {
                assert(result == Err::<(u8,u8),u8>(23u8));
            }
            if steps[start] == policy::PublicationStep::<u8,u8>::Manifest(Ok(4u8))
                && steps[start + 1] == policy::PublicationStep::<u8,u8>::Launcher(Ok(9u8))
                && (steps[start + 2] matches policy::PublicationStep::Rename(Ok(_))) {
                assert(result == Ok::<(u8,u8),u8>((4u8,9u8)));
            }
        }
    }
}

#[cfg_attr(not(verus_keep_ghost), test)]
fn occupied_platforms_are_rejected() {
    let mut platforms = std::collections::BTreeMap::<u64, u8>::new();
    expect(policy::platform_available(&platforms, &2));
    platforms.insert(2, 7);
    expect(!policy::platform_available(&platforms, &2));
    expect(policy::platform_available(&platforms, &3));
}

/// One field at a time and simultaneous failures exercise both value and precedence.
#[cfg_attr(not(verus_keep_ghost), test)]
fn platform_assembly_preserves_source_and_first_error() {
    use policy::{admit_assembly_source, AssemblyError::*, AssemblySource};
    let v1 = "v1".to_string();
    let v2 = "v2".to_string();
    let c1 = "c1".to_string();
    let c2 = "c2".to_string();
    let t1 = "t1".to_string();
    let t2 = "t2".to_string();
    proof {
        reveal_strlit("v1");
        reveal_strlit("v2");
        assert(v1@[1] != v2@[1]);
        reveal_strlit("c1");
        reveal_strlit("c2");
        assert(c1@[1] != c2@[1]);
        reveal_strlit("t1");
        reveal_strlit("t2");
        assert(t1@[1] != t2@[1]);
    }
    let origin = AssemblySource { version: &v1, commit: &c1, tree: &t1 };
    let version = AssemblySource { version: &v2, commit: &c1, tree: &t1 };
    let commit = AssemblySource { version: &v1, commit: &c2, tree: &t1 };
    let tree = AssemblySource { version: &v1, commit: &c1, tree: &t2 };
    expect(admit_assembly_source(None, None, origin).is_ok());
    expect(admit_assembly_source(Some(&v1), Some(origin), origin).is_ok());
    expect(matches!(admit_assembly_source(Some(&v2), None, origin), Err(PromotionVersion)));
    expect(matches!(admit_assembly_source(None, Some(origin), version), Err(DifferentSource)));
    expect(matches!(admit_assembly_source(None, Some(origin), commit), Err(DifferentSource)));
    expect(matches!(admit_assembly_source(Some(&v1), Some(origin), tree), Err(DifferentSource)));
    expect(matches!(admit_assembly_source(Some(&v2), Some(origin), tree), Err(PromotionVersion)));
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
fn cleanup_names_require_the_original_stage_and_member_alphabets() {
    use policy::{valid_stage_id, removable_stage_member};
    let good = [48u8; 16];
    expect(valid_stage_id(&good));
    expect(!valid_stage_id(&[48u8; 15]));
    expect(!valid_stage_id(&[48u8; 17]));
    let mut bad = good;
    bad[15] = 95;
    let rejected = valid_stage_id(&bad);
    assert(bad@[15] == 95);
    expect(!rejected);
    bad[15] = 255;
    let rejected = valid_stage_id(&bad);
    assert(bad@[15] == 255);
    expect(!rejected);
    expect(removable_stage_member(true, true, None));
    expect(!removable_stage_member(false, true, None));
    expect(!removable_stage_member(true, false, None));
    expect(!removable_stage_member(true, false, Some(&[])));
    expect(removable_stage_member(true, false, Some(&[48, 57])));
    expect(!removable_stage_member(false, false, Some(&[48, 57])));
    expect(!removable_stage_member(true, false, Some(&[48, 58])));
    expect(!removable_stage_member(true, false, Some(&[47, 57])));
    expect(!removable_stage_member(true, false, Some(&[48, 200])));
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
    let original = "0123".to_owned();
    let different = "0124".to_owned();
    proof {
        reveal_strlit("0123");
        reveal_strlit("0124");
        assert(original@[3] != different@[3]);
    }
    expect(policy::matches_observed_asset(&original, 10, &original, 10));
    expect(!policy::matches_observed_asset(&original, 10, &different, 10));
    expect(!policy::matches_observed_asset(&original, 10, &original, 11));
    expect(!policy::matches_observed_asset(&original, 10, &different, 11));
}

}

#[cfg(not(verus_keep_ghost))]
#[test]
fn installed_roadmap_and_setup_match_the_rendered_host() {
    use sha2::{Digest, Sha256};
    let sha256 = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    let (roadmap, workflow, installer) = deployed_host_inputs();
    assert!(matches_host_template(
        &sha256(roadmap.as_bytes()),
        &sha256(workflow.as_bytes()),
        &sha256(installer.as_bytes()),
    ));
}
