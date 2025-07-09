// SPDX-License-Identifier: BSD-2-Clause
//! Taken from codesort (<https://github.com/Canop/codesort>) `sort-all-enums` example.
//!
//! Modifications:
//!   - add Ord and bitsize to excluded keywords
//!   - exclude enums with = in definition, indicating their integer representation matters
//!   - bug where multiline attributes were not considered to exclusions
//!   - runs on styx project dir

use {
    codesort::*,
    lazy_regex::*,
    std::{fs, io, path::PathBuf},
    styx_util::styx_root_pathbuf,
    termimad::crossterm::style::Stylize,
};

/// Directories we don't want to touch
static EXCLUDED_DIRS: &[&str] = &[".git", "target", "build"];

/// Keywords which, if found in the annotations before an enum, will
/// prevent the enum variants from being sorted
static EXCLUDING_KEYWORDS: &[&str] = &["repr", "serde", "PartialOrd", "Ord", "bitsize"];

fn get_all_rust_files(
    root: PathBuf,
    include: &[String],
    exclude: &[String],
) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    // if we're given a single file, it's probably because the user
    // wants to sort it, so we don't check the extension
    if !root.is_dir() {
        files.push(root);
        return Ok(files);
    }
    let mut dirs = vec![root];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if path.is_dir() {
                if file_name.starts_with('.') {
                    continue;
                }
                if exclude.iter().any(|ex| ex == file_name) {
                    eprintln!("{} {:?}", "Excluded".yellow(), path);
                    continue;
                }
                if EXCLUDED_DIRS.contains(&file_name) && !include.iter().any(|inc| inc == file_name)
                {
                    eprintln!("{} {:?}", "Excluded".yellow(), path);
                    continue;
                }
                dirs.push(path.to_path_buf());
                continue;
            }
            if let Some(ext) = path.extension() {
                if ext.to_str() == Some("rs") {
                    files.push(path.to_path_buf());
                }
            }
        }
    }
    Ok(files)
}

pub fn execute() -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    let files = get_all_rust_files(styx_root_pathbuf(), &[], &[])?;
    eprintln!("Found {} rust files", files.len());
    let mut sorted_enum_count = 0;
    let mut ok_files_count = 0;
    let mut invalid_files_count = 0;
    let mut incomplete_files_count = 0;
    let mut excluded_enums_count = 0;
    let mut modified_files_count = 0;
    let mut empty_files_count = 0;
    for file in &files {
        let loc_list = LocList::read_file(file, Language::Rust);
        let mut loc_list = match loc_list {
            Ok(loc_list) => loc_list,
            Err(e) => {
                eprintln!("{} in {}: {:?}", "ERROR".red(), file.display(), e);
                invalid_files_count += 1;
                continue;
            }
        };
        if !loc_list.has_content() {
            empty_files_count += 1;
            continue;
        }
        if !loc_list.is_complete() {
            eprintln!(
                "skipping {} ({})",
                file.display(),
                "not consistent enough".yellow()
            );
            incomplete_files_count += 1;
            continue;
        }
        let mut modified = false;
        let mut line_idx = 0;
        ok_files_count += 1;
        while line_idx + 2 < loc_list.len() {
            let loc = &loc_list.locs[line_idx];
            if !loc.starts_normal {
                line_idx += 1;
                continue;
            }
            let content = &loc.content;
            let Some((_, name)) =
                regex_captures!(r"^[\s\w()]*\benum\s+([^({]+)\s+\{\s**$", content)
            else {
                line_idx += 1;
                continue;
            };

            // We look whether the annotations before the enum contain any one
            // of the excluding keywords
            let whole_enum_range = loc_list
                .block_range_of_line_number(LineNumber::from_index(line_idx))
                .unwrap();
            let whole_enum_range = loc_list.trimmed_range(whole_enum_range);
            let excluding_keyword = EXCLUDING_KEYWORDS.iter().find(|&keyword| {
                loc_list.locs[whole_enum_range.start.to_index()..line_idx]
                    .iter()
                    .any(|loc| loc.content.contains(keyword))
            });
            if let Some(excluding_keyword) = excluding_keyword {
                eprintln!("skipping enum {} ({})", name, excluding_keyword.yellow());
                excluded_enums_count += 1;
                line_idx = whole_enum_range.end.to_index() + 1;
                continue;
            }

            // no equals
            let has_eq = loc_list.locs[line_idx..=whole_enum_range.end.to_index()]
                .iter()
                .any(|l| l.sort_key.contains("="));
            if has_eq {
                eprintln!("skipping enum {} (has =)", name);
                excluded_enums_count += 1;
                line_idx = whole_enum_range.end.to_index() + 1;
                continue;
            }

            loc_list
                .print_range_debug(&format!(" sorting enum {} ", name.blue()), whole_enum_range);
            let range = loc_list.range_around_line_index(line_idx + 1).unwrap();
            loc_list.sort_range(range).unwrap();
            line_idx = range.end.to_index() + 2;
            sorted_enum_count += 1;
            modified = true;
        }
        if modified {
            loc_list.write_file(file)?;
            eprintln!("wrote {}", file.display());
            modified_files_count += 1;
        }
    }
    eprintln!("\nDone in {:.3}s\n", start.elapsed().as_secs_f32());
    eprintln!("I analyzed {} files", files.len());
    let mut problems = Vec::new();
    if empty_files_count > 0 {
        problems.push(format!("{} empty files", empty_files_count));
    }
    if incomplete_files_count > 0 {
        problems.push(format!("{} incomplete files", incomplete_files_count));
    }
    if invalid_files_count > 0 {
        problems.push(format!("{} invalid files", invalid_files_count));
    }
    if problems.is_empty() {
        eprintln!("All {} files were ok", ok_files_count);
    } else {
        eprintln!(
            "{} files were OK but I encountered {}",
            ok_files_count,
            problems.join(", ")
        );
    }
    if excluded_enums_count > 0 {
        eprintln!(
            "I excluded {} enums whose annotation contained excluding keywords",
            excluded_enums_count
        );
    }
    eprintln!(
        "I sorted {} enums in {} files",
        sorted_enum_count, modified_files_count
    );
    Ok(())
}
