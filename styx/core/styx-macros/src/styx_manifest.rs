// SPDX-License-Identifier: BSD-2-Clause
// Portions derived from Bevy's BevyManifest (MIT License)
// https://github.com/bevyengine/bevy
// Copyright (c) Bevy Contributors

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};
use std::time::SystemTime;

use toml_edit::Document;

/// Parsed `Cargo.toml` of the crate invoking a proc macro.
///
/// Used to determine how to reference styx crates from generated
/// code, since the correct path depends on which layer of the
/// workspace the calling crate lives in.
#[derive(Debug)]
pub struct StyxManifest {
    manifest: Document<Box<str>>,
    modified_time: SystemTime,
}

impl StyxManifest {
    /// Calls `f` with a global shared instance of the [`StyxManifest`] of the calling crate.
    ///
    /// The manifest is the `Cargo.toml` of the crate that the macro is called
    /// from. Parsed manifests are cached by path and invalidated when the
    /// file's modification time changes.
    pub fn shared<R>(f: impl FnOnce(&StyxManifest) -> R) -> R {
        // Cache of parsed manifests, keyed by Cargo.toml path.
        static MANIFESTS: RwLock<BTreeMap<PathBuf, StyxManifest>> = RwLock::new(BTreeMap::new());
        let manifest_path = Self::get_manifest_path();
        let modified_time = Self::get_manifest_modified_time(&manifest_path)
            .expect("The Cargo.toml should have a modified time");

        // Return the cached manifest if it is still fresh.
        let manifests = MANIFESTS.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(manifest) = manifests.get(&manifest_path) {
            if manifest.modified_time == modified_time {
                return f(manifest);
            }
        }

        // Cache miss or stale entry: re-parse and update the cache.
        drop(manifests);

        let manifest = StyxManifest {
            manifest: Self::read_manifest(&manifest_path),
            modified_time,
        };

        let key = manifest_path.clone();
        // TODO: Switch to using RwLockWriteGuard::downgrade when codebase moves to MSRV 1.92.
        MANIFESTS
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, manifest);

        f(MANIFESTS
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&manifest_path)
            .unwrap())
    }

    fn get_manifest_path() -> PathBuf {
        env::var_os("CARGO_MANIFEST_DIR")
            .map(|path| {
                let mut path = PathBuf::from(path);
                path.push("Cargo.toml");
                assert!(
                    path.exists(),
                    "Cargo manifest does not exist at path {}",
                    path.display()
                );
                path
            })
            .expect("CARGO_MANIFEST_DIR is not defined.")
    }

    fn get_manifest_modified_time(
        cargo_manifest_path: &Path,
    ) -> Result<SystemTime, std::io::Error> {
        std::fs::metadata(cargo_manifest_path).and_then(|metadata| metadata.modified())
    }

    fn read_manifest(path: &Path) -> Document<Box<str>> {
        let manifest = std::fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("Unable to read cargo manifest: {}", path.display()))
            .into_boxed_str();
        Document::parse(manifest)
            .unwrap_or_else(|_| panic!("Failed to parse cargo manifest: {}", path.display()))
    }

    /// Returns the base path to reach `styx_processor` modules
    /// from the calling crate.
    ///
    /// The resolved path depends on how the calling crate relates
    /// to `styx-processor` in the dependency graph:
    ///
    /// | Calling crate | Cargo.toml dep | Resolved base |
    /// |---|---|---|
    /// | `styx-processor` itself | — | `crate` |
    /// | Sibling core crate | `styx-processor` | `::styx_processor` |
    /// | Non-core styx crate | `styx-core` | `::styx_core::processor` |
    /// | External crate | `styx-emulator` | `::styx_emulator::core::processor` |
    pub fn get_processor_path(&self) -> syn::Path {
        if self.package_name() == Some("styx-processor") {
            return Self::parse_str("crate");
        }

        if self.has_dep("styx-processor") {
            Self::parse_str("::styx_processor")
        } else if self.has_dep("styx-core") {
            Self::parse_str("::styx_core")
        } else if self.has_dep("styx-emulator") {
            Self::parse_str("::styx_emulator::processor")
        } else {
            Self::parse_str("::styx_processor")
        }
    }

    /// Returns the `[package].name` from the manifest, if present.
    fn package_name(&self) -> Option<&str> {
        self.manifest.get("package")?.get("name")?.as_str()
    }

    /// Returns `true` if `name` appears in `[dependencies]` or
    /// `[dev-dependencies]`.
    fn has_dep(&self, name: &str) -> bool {
        let in_table = |key: &str| -> bool {
            self.manifest
                .get(key)
                .and_then(|deps| deps.get(name))
                .is_some()
        };
        in_table("dependencies") || in_table("dev-dependencies")
    }

    /// Attempt to parse the provided [path](str) as a
    /// [syntax tree node](syn::parse::Parse).
    pub fn try_parse_str<T: syn::parse::Parse>(path: &str) -> Option<T> {
        syn::parse_str(path).ok()
    }

    /// Attempt to parse provided [path](str) as a
    /// [syntax tree node](syn::parse::Parse).
    ///
    /// # Panics
    ///
    /// Will panic if the path is not able to be parsed. For a
    /// non-panicking option, see [`try_parse_str`].
    ///
    /// [`try_parse_str`]: Self::try_parse_str
    pub fn parse_str<T: syn::parse::Parse>(path: &str) -> T {
        Self::try_parse_str(path).expect("failed to parse path")
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    // Example Cargo.toml in styx-processor.
    const STYX_PROCESSOR_TOML: &str = r#"
        [package]
        name = "styx-processor"
        "#;
    // Example Cargo.toml in styx/core/.
    const STYX_CORE_TOML: &str = r#"
        [dependencies]
        styx-processor = { path = "../styx-processor" }
        "#;
    // Example Cargo.toml in styx/.
    const STYX_TOML: &str = r#"
        [dependencies]
        styx-core = { workspace = true, features = ["arch_ppc"] }
        "#;
    // Example Cargo.toml outside of styx.
    const EXTERNAL_TOML: &str = r#"
        [dependencies]
        styx-emulator = "1.0.0"
        "#;

    /// Test the import path of styx_processor in various Cargo.toml scenarios.
    #[test_case(STYX_PROCESSOR_TOML, "crate")]
    #[test_case(STYX_CORE_TOML, "::styx_processor")]
    #[test_case(STYX_TOML, "::styx_core")]
    #[test_case(EXTERNAL_TOML, "::styx_emulator::processor")]
    fn test_styx_processor_path(toml: &str, path: &str) {
        let manifest =
            Document::parse(toml.to_string().into_boxed_str()).expect("invalid manifest");

        let styx_manifest = StyxManifest {
            manifest,
            // doesn't matter
            modified_time: SystemTime::now(),
        };

        let expected_path = syn::parse_str::<syn::Path>(path).expect("could not parse path");

        let result_path = styx_manifest.get_processor_path();

        assert_eq!(expected_path, result_path);
    }

    /// Test that changing the manifest will invalidate the cache and correctly
    /// reevaluate the manifest.
    #[test]
    fn test_manifest_cache() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let cargo_toml = tmp_dir.path().join("Cargo.toml");

        // Start with a manifest that names styx-processor.
        std::fs::write(&cargo_toml, STYX_PROCESSOR_TOML).unwrap();

        let dir_str = tmp_dir.path().to_str().unwrap().to_owned();
        temp_env::with_var("CARGO_MANIFEST_DIR", Some(&dir_str), || {
            // First call: should parse and cache the manifest.
            let path1 = StyxManifest::shared(|m| m.get_processor_path());
            let expected_crate: syn::Path = syn::parse_str("crate").unwrap();
            assert_eq!(path1, expected_crate, "should resolve to `crate`");

            // Second call without modifying the file: cache hit.
            let path2 = StyxManifest::shared(|m| m.get_processor_path());
            assert_eq!(path2, expected_crate, "cache hit should return same path");

            // Overwrite with STYX_CORE content and a new mtime.
            std::fs::write(&cargo_toml, STYX_CORE_TOML.as_bytes()).unwrap();

            // Third call: cache should be invalidated.
            let path3 = StyxManifest::shared(|m| m.get_processor_path());
            let expected_processor: syn::Path = syn::parse_str("::styx_processor").unwrap();
            assert_eq!(
                path3, expected_processor,
                "stale cache should re-parse and resolve to `::styx_processor`"
            );
        });
    }
}
