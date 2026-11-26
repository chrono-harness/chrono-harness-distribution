//! Distribution knows explicit release members and destinations, never host projects.
#![allow(unexpected_cfgs)]

#[cfg(not(verus_keep_ghost))]
pub mod asset_identity;
#[cfg(not(verus_keep_ghost))]
mod staging;

#[cfg(verus_keep_ghost)]
use super::{hex_digit, valid_hex};
#[cfg(not(verus_keep_ghost))]
use asset_identity::valid_hex;
#[cfg(not(verus_keep_ghost))]
use verus_builtin_macros::verus;
#[cfg(verus_keep_ghost)]
use vstd::{prelude::*, string::StringSliceAdditionalSpecFns};

verus! {
/// Admission of a decoded release header before validating its platform members.
pub fn valid_release_header(schema: &[u8], commit: &[u8], tree: &[u8], platform_count: usize)
    -> (valid: bool)
    ensures valid == (
        schema@ == "chrono-release/v1".spec_bytes() && platform_count > 0
        && commit.len() == 40
        && (forall|i: int| 0 <= i < commit.len() ==> hex_digit(#[trigger] commit[i]))
        && tree.len() == 40
        && (forall|i: int| 0 <= i < tree.len() ==> hex_digit(#[trigger] tree[i]))
    ),
{
    let expected = "chrono-release/v1".as_bytes();
    if schema.len() != expected.len() { return false; }
    let mut i = 0;
    while i < expected.len()
        invariant i <= expected.len(), schema.len() == expected.len(),
            expected@ == "chrono-release/v1".spec_bytes(),
            forall|j: int| 0 <= j < i ==> schema[j] == #[trigger] expected[j],
        decreases expected.len() - i,
    {
        if schema[i] != expected[i] { return false; }
        i += 1;
    }
    assert(schema@ =~= expected@);
    valid_hex(commit, 40) && valid_hex(tree, 40) && platform_count > 0
}
}

#[cfg(not(verus_keep_ghost))]
pub use native::*;
#[cfg(not(verus_keep_ghost))]
use native::{Result, member_path, publish};

#[cfg(not(verus_keep_ghost))]
mod native {
    use super::{asset_identity, staging, valid_release_header};
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use serde_json::{Value, json as value};
    use serde_with::{MapPreventDuplicates, serde_as};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs, io,
        path::{Component, Path, PathBuf},
        process::Command,
    };

    pub(super) type Result<T> = std::result::Result<T, String>;
    const LAUNCHER: &str = include_str!("../../../assets/distribution/bootstrap.sh");
    const LOCK_PATH: &str = ".chrono-harness/distribution.json";
    const BOOTSTRAP_PATH: &str = ".chrono-harness/install.sh";

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Asset {
        pub file: String,
        pub sha256: String,
        pub size: u64,
    }
    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Release {
        pub schema: String,
        pub version: String,
        pub source_commit: String,
        pub source_tree: String,
        #[serde_as(deserialize_as = "MapPreventDuplicates<_, MapPreventDuplicates<_, _>>")]
        pub platforms: BTreeMap<String, BTreeMap<String, Asset>>,
    }
    impl Release {
        fn assembly_source(&self) -> asset_identity::AssemblySource<'_> {
            asset_identity::AssemblySource {
                version: &self.version,
                commit: &self.source_commit,
                tree: &self.source_tree,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
    pub enum Source {
        Https { base_url: String, curl: String },
        Directory { path: PathBuf },
    }
    #[serde_as]
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Lock {
        pub schema: String,
        pub version: String,
        pub source: Source,
        pub manifest: Asset,
        #[serde_as(deserialize_as = "MapPreventDuplicates<_, _>")]
        pub installers: BTreeMap<String, Asset>,
        #[serde_as(deserialize_as = "MapPreventDuplicates<_, _>")]
        pub install: BTreeMap<String, String>,
    }
    #[serde_as]
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Plan {
        schema: String,
        version: String,
        #[serde_as(deserialize_as = "MapPreventDuplicates<_, _>")]
        assets: BTreeMap<String, String>,
    }

    fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
        let file = fs::File::open(path).map_err(|error| error.to_string())?;
        serde_json::from_reader(io::BufReader::new(file)).map_err(|error| error.to_string())
    }
    fn write<T: Serialize>(path: &Path, data: &T) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(data).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        fs::write(path, bytes).map_err(|e| e.to_string())
    }
    fn name(s: &str) -> Result<()> {
        if !asset_identity::valid_name(s.as_bytes()) {
            return Err(format!("invalid release name: {s:?}"));
        }
        Ok(())
    }
    fn asset(a: &Asset) -> Result<()> {
        name(&a.file)?;
        if !asset_identity::valid_asset_identity(a.sha256.as_bytes(), a.size) {
            return Err("invalid asset digest/size".into());
        }
        Ok(())
    }
    fn require_regular_file(path: &Path) -> Result<()> {
        if !fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .is_file()
        {
            return Err(format!("not a regular input file: {}", path.display()));
        }
        Ok(())
    }

    fn file_identity(path: &Path) -> Result<(String, u64)> {
        require_regular_file(path)?;
        let mut file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !file.metadata().map_err(|e| e.to_string())?.is_file() {
            return Err(format!("not a regular input file: {}", path.display()));
        }
        let mut digest = Sha256::new();
        let size = io::copy(&mut file, &mut digest).map_err(|e| e.to_string())?;
        Ok((format!("{:x}", digest.finalize()), size))
    }

    struct MemberComponents<'a> {
        parts: std::path::Components<'a>,
        path: PathBuf,
    }

    impl asset_identity::MemberSource<io::Error> for MemberComponents<'_> {
        fn next(&mut self) -> Option<asset_identity::Observation<io::Error>> {
            use asset_identity::Observation;
            let Component::Normal(part) = self.parts.next()? else {
                return Some(Observation::InvalidComponent);
            };
            self.path.push(part);
            Some(match fs::symlink_metadata(&self.path) {
                Ok(metadata) if metadata.is_symlink() => Observation::Symlink,
                Ok(_) => Observation::Present,
                Err(error) if error.kind() == io::ErrorKind::NotFound => Observation::Missing,
                Err(error) => Observation::Io(error),
            })
        }
    }

    pub(super) fn member_path(root: &Path, member: &str) -> Result<PathBuf> {
        use asset_identity::MemberError;
        let mut source = MemberComponents {
            parts: Path::new(member).components(),
            path: root.to_path_buf(),
        };
        match asset_identity::check_member(member.as_bytes(), &mut source) {
            Ok(()) => Ok(source.path),
            Err(MemberError::InvalidPath) => Err(format!("invalid relative path: {member:?}")),
            Err(MemberError::Symlink) => Err(format!(
                "symlink path is not allowed: {}",
                source.path.display()
            )),
            Err(MemberError::Io(error)) => Err(format!("{}: {error}", source.path.display())),
        }
    }

    fn inspect(path: &Path, file: String) -> Result<Asset> {
        let (sha256, size) = file_identity(path)?;
        let a = Asset { file, sha256, size };
        asset(&a)?;
        Ok(a)
    }
    fn verify(path: &Path, a: &Asset) -> Result<()> {
        asset(a)?;
        let (digest, size) = file_identity(path)?;
        if !asset_identity::matches_observed_asset(&a.sha256, a.size, &digest, size) {
            return Err(format!("integrity mismatch: {}", a.file));
        }
        Ok(())
    }
    pub fn platform() -> String {
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
    }
    fn release(r: &Release) -> Result<()> {
        if !valid_release_header(
            r.schema.as_bytes(),
            r.source_commit.as_bytes(),
            r.source_tree.as_bytes(),
            r.platforms.len(),
        ) {
            return Err("invalid release identity".into());
        }
        name(&r.version)?;
        let mut files = BTreeSet::new();
        let mut members: Option<Vec<&String>> = None;
        for (p, tools) in &r.platforms {
            name(p)?;
            if !tools.contains_key("chrono-distribution") {
                return Err("release has no installer".into());
            }
            let names: Vec<_> = tools.keys().collect();
            if let Some(first) = &members {
                if !asset_identity::same_platform_members(first, &names) {
                    return Err("platform release members differ".into());
                }
            } else {
                members = Some(names);
            }
            for (n, a) in tools {
                name(n)?;
                asset(a)?;
                if a.file != format!("{n}-{p}") || !files.insert(&a.file) {
                    return Err("ambiguous release asset".into());
                }
            }
        }
        Ok(())
    }
    fn source(s: &Source) -> Result<()> {
        match s {
            Source::Directory { path } if path.is_absolute() && path.is_dir() => Ok(()),
            Source::Https { base_url, curl }
                if base_url.starts_with("https://")
                    && base_url.len() > 8
                    && !base_url.contains(['?', '#', '\n', '\r', '@'])
                    && !curl.is_empty() =>
            {
                Ok(())
            }
            _ => Err(
                "source must be an absolute directory or HTTPS base URL with explicit curl".into(),
            ),
        }
    }
    fn lock(l: &Lock) -> Result<()> {
        if l.schema != "chrono-install/v1" || l.install.is_empty() || l.installers.is_empty() {
            return Err("invalid install declaration".into());
        }
        name(&l.version)?;
        asset(&l.manifest)?;
        source(&l.source)?;
        let mut destinations = BTreeSet::new();
        for (n, dst) in &l.install {
            name(n)?;
            let Some(leaf) = dst.strip_prefix(".chrono-harness/bin/") else {
                return Err("tools must install under .chrono-harness/bin/".into());
            };
            name(leaf)?;
            if !destinations.insert(dst) {
                return Err("duplicate install destination".into());
            }
        }
        for (p, a) in &l.installers {
            name(p)?;
            asset(a)?;
            if a.file != format!("chrono-distribution-{p}") {
                return Err("installer platform mismatch".into());
            }
        }
        Ok(())
    }
    fn fetch(s: &Source, a: &Asset, to: &Path, stage: &staging::Stage) -> Result<()> {
        asset(a)?;
        source(s)?;
        match s {
            Source::Directory { path } => {
                let from = member_path(path, &a.file)?;
                fs::copy(from, to).map_err(|e| e.to_string())?;
            }
            Source::Https { base_url, curl } => {
                let mut command = Command::new(curl);
                stage.borrow(&mut command).map_err(|e| e.to_string())?;
                let status = command
                    .args([
                        "--disable",
                        "--fail",
                        "--location",
                        "--silent",
                        "--show-error",
                        "--proto",
                        "=https",
                        "--proto-redir",
                        "=https",
                        "--connect-timeout",
                        "30",
                        "--max-time",
                        "300",
                        "--output",
                    ])
                    .arg(to)
                    .arg("--url")
                    .arg(format!("{}/{}", base_url.trim_end_matches('/'), a.file))
                    .status()
                    .map_err(|e| format!("download: {e}"))?;
                if !status.success() {
                    return Err(format!("download failed: {} ({status})", a.file));
                }
            }
        }
        verify(to, a)
    }
    fn git(root: &Path, args: &[&str]) -> Result<String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into());
        }
        String::from_utf8(out.stdout)
            .map(|s| s.trim().into())
            .map_err(|e| e.to_string())
    }
    /// Package only the plan's already built files from a clean, fixed source tree.
    /// Build provenance/SDK closure is a separate obligation; SHA-256 is byte identity.
    fn pack(root: &Path, assets: &Path, plan: &Path, out: &Path) -> Result<Value> {
        let plan: Plan = read(plan)?;
        if plan.schema != "chrono-release-plan/v1" || plan.assets.is_empty() {
            return Err("invalid release plan".into());
        }
        name(&plan.version)?;
        if !git(root, &["status", "--porcelain"])?.is_empty() {
            return Err("release source tree is dirty".into());
        }
        let commit = git(root, &["rev-parse", "HEAD"])?;
        let tree = git(root, &["rev-parse", "HEAD^{tree}"])?;
        if out.exists() {
            return Err("release output already exists".into());
        }
        let parent = out.parent().ok_or("output has no parent")?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let stage = tempfile::tempdir_in(parent).map_err(|e| e.to_string())?;
        let p = platform();
        let mut tools = BTreeMap::new();
        for (n, path) in plan.assets {
            name(&n)?;
            let from = member_path(assets, &path)?;
            if fs::metadata(&from)
                .map_err(|e| e.to_string())?
                .permissions()
                .mode()
                & 0o111
                == 0
            {
                return Err(format!("not executable: {path}"));
            }
            let file = format!("{n}-{p}");
            fs::copy(from, stage.path().join(&file)).map_err(|e| e.to_string())?;
            tools.insert(n, inspect(&stage.path().join(&file), file)?);
        }
        let r = Release {
            schema: "chrono-release/v1".into(),
            version: plan.version,
            source_commit: commit,
            source_tree: tree,
            platforms: BTreeMap::from([(p.clone(), tools)]),
        };
        release(&r)?;
        write(&stage.path().join("release.json"), &r)?;
        if !git(root, &["status", "--porcelain"])?.is_empty()
            || git(root, &["rev-parse", "HEAD"])? != r.source_commit
        {
            return Err("release source changed while packaging".into());
        }
        fs::rename(stage.path(), out).map_err(|e| e.to_string())?;
        Ok(
            value!({"platform":p,"version":r.version,"source_commit":r.source_commit,"source_tree":r.source_tree}),
        )
    }
    /// Combine explicitly supplied, matching platform packages; no directory discovery.
    fn assemble(
        inputs: &[PathBuf],
        out: &Path,
        origin: Source,
        promotion: Option<(&String, &String)>,
    ) -> Result<Value> {
        source(&origin)?;
        if let Some((from, to)) = promotion {
            name(from)?;
            name(to)?;
            if from == to {
                return Err("promotion needs different input and output versions".into());
            }
        }
        if inputs.is_empty() || out.exists() {
            return Err("need inputs and absent output".into());
        }
        let parent = out.parent().ok_or("output has no parent")?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let stage = tempfile::tempdir_in(parent).map_err(|e| e.to_string())?;
        let mut combined: Option<Release> = None;
        for dir in inputs {
            let r: Release = read(&dir.join("release.json"))?;
            release(&r)?;
            asset_identity::admit_assembly_source(
                promotion.map(|(from, _)| from),
                combined.as_ref().map(Release::assembly_source),
                r.assembly_source(),
            )
            .map_err(|error| match error {
                asset_identity::AssemblyError::PromotionVersion => {
                    "promotion input version differs"
                }
                asset_identity::AssemblyError::DifferentSource => {
                    "platform source/version mismatch"
                }
            })?;
            let c = combined.get_or_insert_with(|| Release {
                schema: r.schema.clone(),
                version: r.version.clone(),
                source_commit: r.source_commit.clone(),
                source_tree: r.source_tree.clone(),
                platforms: BTreeMap::new(),
            });
            for (p, members) in r.platforms {
                if !asset_identity::platform_available(&c.platforms, &p) {
                    return Err(format!("duplicate platform: {p}"));
                }
                for a in members.values() {
                    let from = member_path(dir, &a.file)?;
                    require_regular_file(&from)?;
                    let staged = stage.path().join(&a.file);
                    fs::copy(from, &staged).map_err(|e| e.to_string())?;
                    verify(&staged, a)?;
                }
                c.platforms.insert(p, members);
            }
        }
        let mut r = combined.unwrap();
        if let Some((_, version)) = promotion {
            r.version = version.into();
        }
        release(&r)?;
        let mut output = AssemblyPublication {
            release: &r,
            stage: stage.path(),
            destination: out,
            origin,
        };
        let (identity, bootstrap) = asset_identity::publish_assembly(&mut output)?;
        Ok(
            value!({"manifest":identity,"bootstrap":bootstrap,"version":r.version,"platforms":r.platforms.keys().collect::<Vec<_>>()}),
        )
    }

    struct AssemblyPublication<'a> {
        release: &'a Release,
        stage: &'a Path,
        destination: &'a Path,
        origin: Source,
    }

    impl asset_identity::Publication<Asset, String> for AssemblyPublication<'_> {
        fn manifest(&mut self) -> Result<Asset> {
            let path = self.stage.join("release.json");
            write(&path, self.release)?;
            inspect(&path, "release.json".into())
        }

        fn launcher(&mut self) -> Result<Asset> {
            let members = self
                .release
                .platforms
                .values()
                .next()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            let lock = adoption(
                &self.stage.join("release.json"),
                self.release,
                self.origin.clone(),
                &members,
            )?;
            let path = self.stage.join("install.sh");
            launcher(&path, &lock, None)?;
            inspect(&path, "install.sh".into())
        }

        fn rename(&mut self) -> Result<()> {
            fs::rename(self.stage, self.destination).map_err(|e| e.to_string())
        }
    }

    /// Roll back ordinary rename failures, retaining backups if recovery itself fails.
    /// This does not promise crash atomicity or cooperation from unrelated writers.
    pub(super) fn publish(root: &Path, stage: &Path, entries: &[(PathBuf, String)]) -> Result<()> {
        let mut applied: Vec<(PathBuf, Option<PathBuf>)> = Vec::new();
        for (i, (from, relative)) in entries.iter().enumerate() {
            let action = (|| {
                let to = member_path(root, relative)?;
                if to.exists() && !to.is_file() {
                    return Err(format!("destination is not a file: {relative}"));
                }
                fs::create_dir_all(to.parent().unwrap()).map_err(|e| e.to_string())?;
                let backup = if to.exists() {
                    let saved = stage.join(format!("backup-{i}"));
                    fs::rename(&to, &saved).map_err(|e| e.to_string())?;
                    Some(saved)
                } else {
                    None
                };
                applied.push((to.clone(), backup));
                fs::rename(from, to).map_err(|e| e.to_string())
            })();
            if let Err(error) = action {
                let mut recovery = Vec::new();
                for (to, backup) in applied.into_iter().rev() {
                    if to.exists()
                        && let Err(e) = fs::remove_file(&to)
                    {
                        recovery.push(format!("{}: {e}", to.display()));
                        continue;
                    }
                    if let Some(saved) = backup
                        && let Err(e) = fs::rename(&saved, &to)
                    {
                        recovery.push(format!("{} -> {}: {e}", saved.display(), to.display()));
                    }
                }
                return Err(format!("{error}; rollback errors: {recovery:?}"));
            }
        }
        Ok(())
    }
    struct SelectedTools<'a> {
        available: &'a BTreeMap<String, Asset>,
        destinations: BTreeMap<String, String>,
    }

    impl asset_identity::SelectionIndex for SelectedTools<'_> {
        fn insert(&mut self, name: &String, prefix: &str) -> bool {
            self.destinations
                .insert(name.clone(), prefix.to_owned() + name)
                .is_some()
        }

        fn contains(&self, name: &String) -> bool {
            self.available.contains_key(name)
        }
    }

    fn adoption(manifest: &Path, r: &Release, origin: Source, members: &[String]) -> Result<Lock> {
        source(&origin)?;
        // release() has already required every platform to publish the same names.
        let available = r
            .platforms
            .values()
            .next()
            .ok_or("invalid release identity")?;
        let mut selected = SelectedTools {
            available,
            destinations: BTreeMap::new(),
        };
        match asset_identity::select_members(members, &mut selected) {
            Ok(()) => {}
            Err(asset_identity::SelectionError::Duplicate) => {
                return Err("duplicate selected member".into());
            }
            Err(asset_identity::SelectionError::Unknown(i)) => {
                return Err(format!("unknown release member: {}", members[i]));
            }
        }
        let l = Lock {
            schema: "chrono-install/v1".into(),
            version: r.version.clone(),
            source: origin,
            manifest: inspect(manifest, "release.json".into())?,
            installers: r
                .platforms
                .iter()
                .map(|(p, t)| (p.clone(), t["chrono-distribution"].clone()))
                .collect(),
            install: selected.destinations,
        };
        lock(&l)?;
        Ok(l)
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    /// A launcher must reject bad arguments before fetching its first executable.
    fn argument_cases(adopt: bool) -> String {
        use asset_identity::{LauncherAction::*, LauncherOption, LauncherValue};
        let mut cases: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for (key, option) in [
            ("host", LauncherOption::Host),
            ("tool", LauncherOption::Tool),
            ("replace", LauncherOption::Replace),
            ("unknown", LauncherOption::Unknown),
        ] {
            for seen in [false, true] {
                for (label, value) in [
                    ("missing", LauncherValue::Missing),
                    ("name", LauncherValue::Name),
                    ("other", LauncherValue::Other),
                ] {
                    let command = match asset_identity::launcher_action(adopt, option, seen, value)
                    {
                        SetHost => "host_root=$2; host_seen=true; shift 2",
                        AddTool => r#"tools="$tools $2"; shift 2"#,
                        SetReplace => "replace=true; shift",
                        MissingHost => "fail 'missing --host-root value'",
                        DuplicateHost => "fail 'duplicate --host-root'",
                        InstallTool => "fail '--tool is only valid for release adoption'",
                        MissingTool => "fail 'missing --tool value'",
                        InvalidTool => "fail 'invalid tool name'",
                        InstallReplace => "fail '--replace is only valid for release adoption'",
                        DuplicateReplace => "fail 'duplicate --replace'",
                        Unknown => r#"fail "unknown option: $1""#,
                    };
                    cases
                        .entry(command)
                        .or_default()
                        .push(format!("{key}:{seen}:{label}"));
                }
            }
        }
        cases
            .into_iter()
            .map(|(command, patterns)| format!("            {}) {command} ;;", patterns.join("|")))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Generate a launcher from validated declarations; the shell never parses JSON.
    fn launcher(path: &Path, l: &Lock, bound_lock: Option<&Asset>) -> Result<()> {
        lock(l)?;
        let (kind, location, curl) = match &l.source {
            Source::Directory { path } => (
                "directory",
                path.to_str().ok_or("source directory must be UTF-8")?,
                "",
            ),
            Source::Https { base_url, curl } => ("https", base_url.as_str(), curl.as_str()),
        };
        let defaults = l.install.keys().cloned().collect::<Vec<_>>().join(" ");
        let mut declarations = String::new();
        for (name, value) in [
            (
                "mode",
                if bound_lock.is_some() {
                    "install"
                } else {
                    "adopt"
                },
            ),
            ("version", l.version.as_str()),
            ("source_kind", kind),
            ("source_location", location),
            ("curl", curl),
            ("default_tools", defaults.as_str()),
            ("manifest_sha256", l.manifest.sha256.as_str()),
            ("manifest_size", &l.manifest.size.to_string()),
        ] {
            declarations.push_str(&format!("    {name}={}\n", shell_quote(value)));
        }
        if let Some(a) = bound_lock {
            declarations.push_str(&format!(
                "    lock_sha256={}\n    lock_size={}\n",
                shell_quote(&a.sha256),
                a.size
            ));
        }
        let mut installers = String::new();
        for (platform, a) in &l.installers {
            installers.push_str(&format!(
                "        {}) installer_sha256={}; installer_size={} ;;\n",
                shell_quote(platform),
                shell_quote(&a.sha256),
                a.size
            ));
        }
        let rendered = LAUNCHER
            .replace("@ARGUMENTS@", &argument_cases(bound_lock.is_none()))
            .replace("@INSTALLERS@", &installers)
            .replace("@DECLARATIONS@", &declarations);
        fs::write(path, rendered).map_err(|e| e.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())
    }

    pub fn adopt(
        root: &Path,
        manifest: &Path,
        origin: Source,
        members: &[String],
        replace: bool,
    ) -> Result<Value> {
        let r: Release = read(manifest)?;
        release(&r)?;
        let l = adoption(manifest, &r, origin, members)?;
        let guard = staging::Guard::acquire(root)?;
        let stage = guard.stage()?;
        write(&stage.path().join("lock"), &l)?;
        let bound_lock = inspect(&stage.path().join("lock"), "distribution.json".into())?;
        launcher(&stage.path().join("launcher"), &l, Some(&bound_lock))?;
        let entries: Vec<(PathBuf, String)> = vec![
            (stage.path().join("lock"), LOCK_PATH.into()),
            (stage.path().join("launcher"), BOOTSTRAP_PATH.into()),
        ];
        for (from, dst) in &entries {
            let path = member_path(root, dst)?;
            if path.exists()
                && !replace
                && fs::read(path).map_err(|e| e.to_string())?
                    != fs::read(from).map_err(|e| e.to_string())?
            {
                return Err(format!(
                    "existing adoption differs: {dst}; use --replace for an explicit update"
                ));
            }
        }
        stage.publish(root, &entries)?;
        Ok(value!({"version":l.version,"lock":LOCK_PATH,"bootstrap":BOOTSTRAP_PATH}))
    }
    pub fn install(root: &Path) -> Result<Value> {
        let l: Lock = read(&member_path(root, LOCK_PATH)?)?;
        lock(&l)?;
        let p = platform();
        let bootstrap = l
            .installers
            .get(&p)
            .ok_or_else(|| format!("unregistered platform: {p}"))?;
        let guard = staging::Guard::acquire(root)?;
        let stage = guard.stage()?;
        let manifest = stage.path().join("release.json");
        fetch(&l.source, &l.manifest, &manifest, &stage)?;
        let r: Release = read(&manifest)?;
        release(&r)?;
        if r.version != l.version {
            return Err("locked release version mismatch".into());
        }
        let tools = r
            .platforms
            .get(&p)
            .ok_or("release lacks current platform")?;
        if tools.get("chrono-distribution") != Some(bootstrap) {
            return Err("locked installer identity mismatch".into());
        }
        let mut entries = Vec::new();
        let mut installed = Vec::new();
        for (n, dst) in &l.install {
            let a = tools
                .get(n)
                .ok_or_else(|| format!("unregistered release member: {n}"))?;
            let to = member_path(root, dst)?;
            if to.exists() && !to.is_file() {
                return Err(format!("destination is not a file: {dst}"));
            }
            // Existing bytes are a cache only after verification; executable mode is part of usable installation.
            let reusable = to.is_file()
                && verify(&to, a).is_ok()
                && fs::metadata(&to)
                    .map_err(|e| e.to_string())?
                    .permissions()
                    .mode()
                    & 0o111
                    != 0;
            if !reusable {
                let from = stage.path().join(format!("payload-{}", entries.len()));
                fetch(&l.source, a, &from, &stage)?;
                fs::set_permissions(&from, fs::Permissions::from_mode(0o755))
                    .map_err(|e| e.to_string())?;
                entries.push((from, dst.clone()));
            }
            installed.push(value!({"name":n,"path":dst,"sha256":a.sha256,"size":a.size}));
        }
        let report = value!({"schema":"chrono-install-result/v1","version":r.version,"source_commit":r.source_commit,"source_tree":r.source_tree,"platform":p,"manifest":l.manifest,"installed":installed});
        stage.publish(root, &entries)?;
        Ok(report)
    }

    pub fn run(args: &[String]) -> Result<Value> {
        if args == ["--version"] {
            return Ok(value!(concat!(
                "chrono-distribution ",
                env!("CARGO_PKG_VERSION")
            )));
        }
        let command = args.first().ok_or("expected pack/assemble/adopt/install")?;
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut i = 1;
        while i < args.len() {
            let key = &args[i];
            if key == "--replace" {
                values.entry(key.clone()).or_default().push("true".into());
                i += 1;
            } else {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {key}"))?;
                values.entry(key.clone()).or_default().push(val.clone());
                i += 2;
            }
        }
        let allowed: &[&str] = match command.as_str() {
            "pack" => &["--root", "--asset-root", "--plan", "--output"],
            "assemble" => &[
                "--input",
                "--output",
                "--source-dir",
                "--base-url",
                "--curl",
                "--from-version",
                "--version",
            ],
            "adopt" => &[
                "--host-root",
                "--manifest",
                "--source-dir",
                "--base-url",
                "--curl",
                "--tool",
                "--replace",
            ],
            "install" => &["--host-root"],
            "maintain" => &["--host-root", "--keep-seconds"],
            _ => return Err("expected pack/assemble/adopt/install".into()),
        };
        for (k, v) in &values {
            if !allowed.contains(&k.as_str()) || (v.len() != 1 && k != "--input" && k != "--tool") {
                return Err(format!("unknown/duplicate option: {k}"));
            }
        }
        let get = |key: &str| -> Result<&str> {
            values
                .get(key)
                .and_then(|v| v.first())
                .map(|s| s.as_str())
                .ok_or_else(|| format!("missing {key}"))
        };
        let origin = || -> Result<Source> {
            match (
                values.contains_key("--source-dir"),
                values.contains_key("--base-url"),
            ) {
                (true, false) if !values.contains_key("--curl") => Ok(Source::Directory {
                    path: PathBuf::from(get("--source-dir")?)
                        .canonicalize()
                        .map_err(|e| e.to_string())?,
                }),
                (false, true) => Ok(Source::Https {
                    base_url: get("--base-url")?.into(),
                    curl: get("--curl")?.into(),
                }),
                _ => Err("choose one source: --source-dir or --base-url with --curl".into()),
            }
        };
        match command.as_str() {
            "pack" => pack(
                Path::new(get("--root")?),
                Path::new(
                    values
                        .get("--asset-root")
                        .map(|v| v[0].as_str())
                        .unwrap_or(get("--root")?),
                ),
                Path::new(get("--plan")?),
                Path::new(get("--output")?),
            ),
            "assemble" => {
                let promotion = match (values.get("--from-version"), values.get("--version")) {
                    (None, None) => None,
                    (Some(from), Some(to)) => Some((&from[0], &to[0])),
                    _ => {
                        return Err("--from-version and --version must be supplied together".into());
                    }
                };
                assemble(
                    &values
                        .get("--input")
                        .ok_or("missing --input")?
                        .iter()
                        .map(PathBuf::from)
                        .collect::<Vec<_>>(),
                    Path::new(get("--output")?),
                    origin()?,
                    promotion,
                )
            }
            "install" => install(Path::new(get("--host-root")?)),
            "maintain" => {
                let seconds = get("--keep-seconds")?
                    .parse::<u64>()
                    .map_err(|e| e.to_string())?;
                let removed = staging::maintain(Path::new(get("--host-root")?), seconds)?;
                Ok(value!({"removed":removed}))
            }
            "adopt" => {
                let s = origin()?;
                adopt(
                    Path::new(get("--host-root")?),
                    Path::new(get("--manifest")?),
                    s,
                    values.get("--tool").ok_or("missing --tool")?,
                    values.contains_key("--replace"),
                )
            }
            _ => unreachable!(),
        }
    }
}
