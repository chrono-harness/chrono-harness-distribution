//! Admission of release member names and the lowercase hexadecimal identities used by the manifest.
#![allow(unexpected_cfgs)]
#[cfg(not(verus_keep_ghost))]
use verus_builtin_macros::verus;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

verus! {

/// Identity of the regular inode reported for the operation marker and this host's gate.
pub fn same_install_file(left_regular: bool, left_dev: u64, left_ino: u64,
    right_regular: bool, right_dev: u64, right_ino: u64) -> (same: bool)
    ensures same == (left_regular && right_regular && left_dev == right_dev && left_ino == right_ino),
{
    left_regular && right_regular && left_dev == right_dev && left_ino == right_ino
}

pub fn install_stage_expired(keep: u64, elapsed: Option<u64>) -> (ready: bool)
    ensures ready == (elapsed is Some && elapsed->Some_0 >= keep),
{
    match elapsed {Some(age) => age >= keep, None => false}
}

/// The installer classifies raw argv words and its two previously-seen flags.
#[derive(Clone, Copy)]
pub enum LauncherOption { Host, Tool, Replace, Unknown }
#[derive(Clone, Copy)]
pub enum LauncherValue { Missing, Name, Other }
pub enum LauncherAction {
    SetHost, AddTool, SetReplace, MissingHost, DuplicateHost, InstallTool,
    MissingTool, InvalidTool, InstallReplace, DuplicateReplace, Unknown,
}

/// This decision is evaluated by the release producer for every reachable shell
/// observation. Unknown arguments and missing operands fail before any IO.
pub fn launcher_action(adopt: bool, option: LauncherOption, seen: bool, value: LauncherValue)
    -> (out: LauncherAction)
    ensures
        match option {
            LauncherOption::Host => if value == LauncherValue::Missing { out == LauncherAction::MissingHost }
                else if seen { out == LauncherAction::DuplicateHost } else { out == LauncherAction::SetHost },
            LauncherOption::Tool => if !adopt { out == LauncherAction::InstallTool }
                else { match value { LauncherValue::Missing => out == LauncherAction::MissingTool,
                    LauncherValue::Name => out == LauncherAction::AddTool,
                    LauncherValue::Other => out == LauncherAction::InvalidTool } },
            LauncherOption::Replace => if !adopt { out == LauncherAction::InstallReplace }
                else if seen { out == LauncherAction::DuplicateReplace } else { out == LauncherAction::SetReplace },
            LauncherOption::Unknown => out == LauncherAction::Unknown,
        },
{
    use LauncherAction::*;
    match option {
        LauncherOption::Host => match value {
            LauncherValue::Missing => MissingHost,
            _ if seen => DuplicateHost,
            _ => SetHost,
        },
        LauncherOption::Tool if !adopt => InstallTool,
        LauncherOption::Tool => match value {
            LauncherValue::Missing => MissingTool,
            LauncherValue::Name => AddTool,
            LauncherValue::Other => InvalidTool,
        },
        LauncherOption::Replace if !adopt => InstallReplace,
        LauncherOption::Replace if seen => DuplicateReplace,
        LauncherOption::Replace => SetReplace,
        LauncherOption::Unknown => Unknown,
    }
}

/// Membership in a validated platform manifest and the local map being constructed.
pub trait SelectionIndex {
    spec fn available(&self) -> Set<Seq<char>>;
    spec fn destinations(&self) -> Map<Seq<char>, Seq<char>>;

    /// Insert the prefixed name, returning the BTreeMap's original occupancy.
    fn insert(&mut self, name: &String, prefix: &str) -> (occupied: bool)
        ensures
            occupied == old(self).destinations().contains_key(name@),
            self.destinations() == old(self).destinations().insert(name@, prefix@ + name@),
            self.available() == old(self).available();

    fn contains(&self, name: &String) -> (known: bool)
        ensures known == self.available().contains(name@);
}

pub enum SelectionError {
    Duplicate,
    Unknown(usize),
}

pub open spec fn different_names(names: Seq<String>, n: int) -> bool {
    forall|i: int, j: int| 0 <= i < j < n ==> names[i]@ != names[j]@
}

pub open spec fn exact_selection(names: Seq<String>, n: int, chosen: Map<Seq<char>, Seq<char>>) -> bool {
    &&& forall|k: Seq<char>| chosen.contains_key(k) <==> exists|i: int| 0 <= i < n && (#[trigger] names[i])@ == k
    &&& forall|i: int| 0 <= i < n ==> chosen[(#[trigger] names[i])@] == ".chrono-harness/bin/"@ + names[i]@
}

pub open spec fn selection_outcome(names: Seq<String>, available: Set<Seq<char>>,
    destinations: Map<Seq<char>, Seq<char>>, out: Result<(), SelectionError>) -> bool {
    match out {
            Err(SelectionError::Duplicate) => !different_names(names, names.len() as int),
            Err(SelectionError::Unknown(i)) => {
                &&& different_names(names, names.len() as int)
                &&& i < names.len() && !available.contains(names[i as int]@)
                &&& forall|j: int| 0 <= j < i ==> available.contains((#[trigger] names[j])@)
            },
            Ok(()) => {
                &&& different_names(names, names.len() as int)
                &&& exact_selection(names, names.len() as int, destinations)
                &&& forall|j: int| 0 <= j < names.len() ==> available.contains((#[trigger] names[j])@)
            },
        }
}

pub fn select_members<T: SelectionIndex>(names: &[String], index: &mut T) -> (out: Result<(), SelectionError>)
    requires old(index).destinations() == Map::<Seq<char>, Seq<char>>::empty(),
    ensures
        index.available() == old(index).available(),
        selection_outcome(names@, old(index).available(), index.destinations(), out),
{
    let mut i = 0;
    while i < names.len()
        invariant
            i <= names.len(),
            index.available() == old(index).available(),
            different_names(names@, i as int),
            exact_selection(names@, i as int, index.destinations()),
        decreases names.len() - i,
    {
        let ghost before = index.destinations();
        if index.insert(&names[i], ".chrono-harness/bin/") {
            proof {
                let j = choose|j: int| 0 <= j < i && (#[trigger] names@[j])@ == names@[i as int]@;
                assert(names@[j]@ == names@[i as int]@);
            }
            return Err(SelectionError::Duplicate);
        }
        proof {
            assert forall|k: Seq<char>| index.destinations().contains_key(k) <==>
                exists|j: int| 0 <= j < i + 1 && (#[trigger] names@[j])@ == k by {
                if k == names@[i as int]@ { assert(i < i + 1); }
            }
        }
        i += 1;
    }
    i = 0;
    while i < names.len()
        invariant
            i <= names.len(), index.available() == old(index).available(),
            different_names(names@, names.len() as int),
            exact_selection(names@, names.len() as int, index.destinations()),
            forall|j: int| 0 <= j < i ==> index.available().contains((#[trigger] names@[j])@),
        decreases names.len() - i,
    {
        if !index.contains(&names[i]) { return Err(SelectionError::Unknown(i)); }
        i += 1;
    }
    Ok(())
}

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

/// Compare the declared asset with the digest and byte count from the same read.
pub fn matches_observed_asset(
    declared_digest: &String, declared_size: u64, observed_digest: &String, observed_size: u64,
) -> (matches: bool)
    ensures matches == (declared_digest@ == observed_digest@ && declared_size == observed_size),
{
    declared_size == observed_size && declared_digest.eq(observed_digest)
}

/// The three manifest fields that must match across a release's platforms.
#[derive(Clone, Copy)]
pub struct AssemblySource<'a> {
    pub version: &'a String,
    pub commit: &'a String,
    pub tree: &'a String,
}

pub enum AssemblyError { PromotionVersion, DifferentSource }

pub fn admit_assembly_source(
    requested: Option<&String>, first: Option<AssemblySource>, input: AssemblySource,
) -> (out: Result<(), AssemblyError>)
    ensures
        match requested {
            Some(version) => (out matches Err(AssemblyError::PromotionVersion)) == (version@ != input.version@),
            None => !(out matches Err(AssemblyError::PromotionVersion)),
        },
        !(out matches Err(AssemblyError::PromotionVersion)) ==> match first {
            None => out.is_ok(),
            Some(source) => out.is_ok() == (
                source.version@ == input.version@ && source.commit@ == input.commit@ && source.tree@ == input.tree@
            ),
        },
{
    if let Some(version) = requested {
        if !version.eq(input.version) { return Err(AssemblyError::PromotionVersion); }
    }
    if let Some(source) = first {
        if !source.version.eq(input.version) || !source.commit.eq(input.commit) || !source.tree.eq(input.tree) {
            return Err(AssemblyError::DifferentSource);
        }
    }
    Ok(())
}

pub open spec fn member_byte(b: u8) -> bool {
    b != 0 && b != 13 && b != 10 && b != 92
}

pub open spec fn member_text(s: Seq<u8>) -> bool {
    s.len() > 0 && forall|i: int| 0 <= i < s.len() ==> member_byte(#[trigger] s[i])
}

fn valid_member_text(s: &[u8]) -> (valid: bool)
    ensures valid == member_text(s@),
{
    if s.is_empty() { return false; }
    let mut i = 0;
    while i < s.len()
        invariant i <= s.len(), forall|j: int| 0 <= j < i ==> member_byte(#[trigger] s[j]),
        decreases s.len() - i,
    {
        let b = s[i];
        if b == 0 || b == 13 || b == 10 || b == 92 { return false; }
        i += 1;
    }
    true
}

/// One Rust component and, for a normal component, the OS observation at its prefix.
pub enum Observation<E> {
    InvalidComponent,
    Present,
    Missing,
    Symlink,
    Io(E),
}

pub enum MemberError<E> {
    InvalidPath,
    Symlink,
    Io(E),
}

pub trait MemberSource<E> {
    spec fn pending(&self) -> Seq<Observation<E>>;

    fn next(&mut self) -> (obs: Option<Observation<E>>)
        ensures
            old(self).pending().len() == 0 ==> obs == None::<Observation<E>> && self.pending() == old(self).pending(),
            old(self).pending().len() > 0 ==> obs == Some(old(self).pending().first())
                && self.pending() == old(self).pending().drop_first();
}

pub open spec fn first_error<E>(steps: Seq<Observation<E>>) -> Result<(), MemberError<E>>
    decreases steps.len(),
{
    if steps.len() == 0 { Ok(()) } else {
        match steps.first() {
            Observation::InvalidComponent => Err(MemberError::InvalidPath),
            Observation::Symlink => Err(MemberError::Symlink),
            Observation::Io(e) => Err(MemberError::Io(e)),
            Observation::Present | Observation::Missing => first_error(steps.drop_first()),
        }
    }
}

pub fn check_member<E, S: MemberSource<E>>(text: &[u8], source: &mut S) -> (out: Result<(), MemberError<E>>)
    ensures
        member_text(text@) ==> out == first_error(old(source).pending()),
        !member_text(text@) ==> out == Result::<(), MemberError<E>>::Err(MemberError::InvalidPath) && source.pending() == old(source).pending(),
{
    if !valid_member_text(text) { return Err(MemberError::InvalidPath); }
    loop
        invariant member_text(text@), first_error(source.pending()) == first_error(old(source).pending()),
        decreases source.pending().len(),
    {
        match source.next() {
            None => return Ok(()),
            Some(Observation::InvalidComponent) => return Err(MemberError::InvalidPath),
            Some(Observation::Symlink) => return Err(MemberError::Symlink),
            Some(Observation::Io(e)) => return Err(MemberError::Io(e)),
            Some(Observation::Missing) | Some(Observation::Present) => (),
        }
    }
}
}
