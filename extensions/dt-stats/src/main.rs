// SPDX-License-Identifier: BSD-2-Clause
//! dt-stats - command-line tool for recovering statistics about collections of device trees.
use clap::{self, Parser};
use fdt::{standard_nodes::Compatible, Fdt};
use globwalk::GlobWalkerBuilder;
use rayon::prelude::*;
use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize,
};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs::{self},
    io::stdout,
    ops::Deref,
    path::PathBuf,
    process::{exit, Command, Stdio},
};

fn main() {
    let mut opts = Cli::parse();

    if !opts.input_dir.is_dir() {
        eprintln!(
            "Error. '{}' is not a directory",
            opts.input_dir.to_string_lossy()
        );
        exit(-1);
    }

    // Globwalker is a horrible library and if the user's input starts with exactly 1 "./" it
    // crashes. If you put "././" it's fine, and if you put "../" it's fine. They had one job.
    while let Ok(stripped) = opts.input_dir.strip_prefix("./") {
        opts.input_dir = stripped.to_path_buf();
    }

    // User has specified a path to a folder containing the zephyr project
    // This includes both the main zephyr repo and a bunch of HALs for
    // specific devices, that all have folders which need to be included.
    // This just includes them so the user doesn't have to use too many args.
    if let Some(ref zephdir) = opts.zephyr_proj_dir {
        // See the pre_dt.cmake file in zephyr
        // We just include every arch because I don't think there are conflicts
        for item in zephdir.join("zephyr/dts/").read_dir().unwrap().flatten() {
            if item.file_type().unwrap().is_dir() {
                opts.isystem
                    .push(zephdir.join("zephyr/dts/").join(item.file_name()));
            }
        }
        opts.isystem.push(zephdir.join("zephyr/dts/"));
        opts.isystem.push(zephdir.join("zephyr/include/"));
        opts.isystem.push(zephdir.join("zephyr/include/zephyr"));
        // Now time to include all the fun HALs
        opts.isystem.push(zephdir.join("modules/hal/stm32/dts"));
        opts.isystem.push(zephdir.join("modules/hal/nxp/dts"));
        opts.isystem.push(zephdir.join("modules/hal/atmel/include"));
        opts.isystem
            .push(zephdir.join("modules/hal/gigadevice/include")); // ~ 10 devices
        opts.isystem
            .push(zephdir.join("modules/hal/bouffalolab/include/zephyr")); // ~ 3 devices
        opts.isystem.push(zephdir.join("modules/hal/ti/dts")); // 1 device
        opts.isystem
            .push(zephdir.join("modules/hal/microchip/include"));
        opts.isystem.push(zephdir.join("modules/hal/microchip/dts")); // ~ 4 w/ above
        opts.isystem.push(zephdir.join("modules/hal/nuvoton/dts")); // ~ 4
    }

    let mut meta_stats = MetaStats {
        found: 0,
        compiled: 0,
        parsed: 0,
    };

    let binaries = make_binaries(&opts, &mut meta_stats);
    let trees = parse_binaries(&binaries, &mut meta_stats);

    let bus_stats = find_bus_members(&trees);
    let perif_stats = find_peripherals(&trees);

    let final_stats = OverallStats {
        meta: meta_stats,
        buses: bus_stats.into_boxed_slice(),
        peripherals: perif_stats.into_values().collect(),
    };

    // Write out final results
    serde_json::to_writer_pretty(stdout(), &final_stats).unwrap();
}

#[derive(Serialize)]
struct OverallStats<'a> {
    meta: MetaStats,
    buses: Box<[BusStats<'a>]>,
    peripherals: Box<[PeriphStats<'a>]>,
}

fn find_bus_members<'a>(trees: &'a [Fdt]) -> Vec<BusStats<'a>> {
    // NOTE: We don't have parent access imma lose my mind

    let mut all_bus_stats = HashMap::<&str, BusStats>::new();
    for tree in trees {
        for node in tree.all_nodes() {
            // If we don't have children just skip this node
            if node.children().peekable().peek().is_none() {
                continue;
            }
            if let Some(buskinds) = node.compatible() {
                for buskind in buskinds.all() {
                    let bus_stats = all_bus_stats
                        .entry(buskind)
                        .or_insert_with(|| BusStats::new(buskind));
                    for child in node.children() {
                        // We now have a child on bus 'buskind' and need to add its stats to the
                        // bus
                        if child.compatible().is_none() {
                            continue;
                        }
                        for child_driv in child.compatible().unwrap().all() {
                            let member_stats = bus_stats
                                .member_stats
                                .entry(child_driv)
                                .or_insert_with(|| BusMemberStats::new(child_driv));
                            member_stats.occurrences += 1;
                            let reg = child.reg().and_then(|mut iter| iter.next());
                            if reg.is_none() {
                                continue;
                            }
                            let member_addrs: usize = reg.unwrap().starting_address as usize;
                            let addr_stats = member_stats
                                .addr_occurrences
                                .entry(member_addrs)
                                .or_insert(0);
                            *addr_stats += 1;
                        }
                    }
                }
            }
        }
    }

    all_bus_stats.into_values().collect()
}

#[derive(Serialize)]
struct BusStats<'a> {
    #[serde(rename = "kind")]
    bus_kind: &'a str,
    #[serde(rename = "members")]
    #[serde(serialize_with = "serialize_as_vals")]
    member_stats: HashMap<&'a str, BusMemberStats<'a>>,
}

impl<'a> BusStats<'a> {
    pub fn new(kind: &'a str) -> BusStats<'a> {
        Self {
            bus_kind: kind,
            member_stats: HashMap::new(),
        }
    }
}

#[derive(Serialize)]
struct BusMemberStats<'a> {
    #[serde(rename = "name")]
    member_name: &'a str,
    occurrences: u32,
    #[serde(rename = "addresses")]
    #[serde(serialize_with = "serialize_hex_map")]
    addr_occurrences: HashMap<usize, u32>,
}

impl<'a> BusMemberStats<'a> {
    pub fn new(kind: &'a str) -> BusMemberStats<'a> {
        Self {
            member_name: kind,
            occurrences: 0,
            addr_occurrences: HashMap::new(),
        }
    }
}

fn find_peripherals<'a>(trees: &'a [Fdt]) -> HashMap<&'a str, PeriphStats<'a>> {
    let mut periph_info = HashMap::new();
    for tree in trees {
        let soc = match tree.find_node("/soc") {
            Some(soc) => soc,
            None => continue,
        };
        for periph in soc.children() {
            // Holy one-liner
            for compat in (periph.compatible().map(Compatible::all))
                .into_iter()
                .flatten()
            {
                let periph_entry = periph_info.entry(compat).or_insert_with(|| PeriphStats {
                    periph_name: compat,
                    occurrences: 0,
                    addr_occurrences: HashMap::new(),
                });
                periph_entry.occurrences += 1;
                let periph_addr: usize = match periph.reg().and_then(|mut r| r.next()) {
                    Some(region) => region.starting_address as usize,
                    _ => continue,
                };
                let addr_entry = periph_entry
                    .addr_occurrences
                    .entry(periph_addr)
                    .or_insert(0);
                *addr_entry += 1;
            }
        }
    }
    periph_info
}

#[derive(Serialize)]
struct PeriphStats<'a> {
    /// Name of the peripheral
    #[serde(rename = "name")]
    periph_name: &'a str,
    /// Total occurrences
    occurrences: u32,
    // /// Architectures it occurrs on
    // arch_occurrences: Vec<&'a str>,
    /// Counts of where this peripheral is located in mmio
    #[serde(rename = "addrs")]
    #[serde(serialize_with = "serialize_hex_map")]
    addr_occurrences: HashMap<usize, u32>,
}

fn serialize_hex_map<S, V>(map: &HashMap<usize, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    V: serde::Serialize,
{
    let mut map_ser = serializer.serialize_map(Some(map.len()))?;
    for (k, v) in map.iter() {
        map_ser.serialize_entry(&format!("0x{k:X}"), &v)?;
    }
    map_ser.end()
}

fn serialize_as_vals<S, V, K>(map: &HashMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    V: serde::Serialize,
{
    let mut seq_ser = serializer.serialize_seq(Some(map.len()))?;
    for (_, v) in map.iter() {
        seq_ser.serialize_element(v)?;
    }
    seq_ser.end()
}

fn parse_binaries<'a, BinData>(bins: &'a [BinData], meta_stats: &mut MetaStats) -> Box<[Fdt<'a>]>
where
    BinData: Deref<Target = [u8]>,
{
    // Effectively instant so no need to parallelize again
    eprintln!("\nParsing dtbs!");
    let trees: Box<[Fdt]> = bins
        .iter()
        .filter_map(|rawbin| match Fdt::new(rawbin) {
            Ok(fdt) => Some(fdt),
            Err(e) => {
                eprintln!("Failed to compile devicetree with err: {e}");
                None
            }
        })
        .collect();
    eprintln!(
        "Successfully parsed {} dtbs! ({} failed)",
        trees.len(),
        bins.len() - trees.len()
    );

    meta_stats.parsed = trees.len();

    trees
}

fn make_binaries(opts: &Cli, meta_stats: &mut MetaStats) -> Box<[Box<[u8]>]> {
    eprintln!("Loading dts/dtb files...");
    let glob = if opts.no_dts {
        "*.dtb"
    } else if opts.no_dtb {
        "*.dts"
    } else {
        "*.{dtb,dts}"
    };
    let allfiles = GlobWalkerBuilder::from_patterns(&opts.input_dir, &[glob])
        .build()
        .unwrap();

    enum DTreeType {
        Dts,
        Dtb,
    }

    let relevant_files = allfiles.filter_map(|file| {
        let file = file.map_or(None, |f| Some(f.into_path()))?;
        if file.extension().is_some_and(|ext| ext == "dts") {
            Some((file, DTreeType::Dts))
        } else if file.extension().is_some_and(|ext| ext == "dtb") {
            Some((file, DTreeType::Dtb))
        } else {
            None
        }
    });

    let mut final_found_count: usize = 0;
    let par_files = relevant_files
        .inspect(|_| final_found_count += 1)
        .par_bridge();
    let compiled_devtrees: Box<[Box<[u8]>]> = par_files
        .filter_map(|(file, ftype)| {
            match ftype {
                DTreeType::Dts => {
                    let osjoin = |a, b| {
                        let mut arg = OsString::new();
                        arg.push(a);
                        arg.push(b);
                        arg
                    };

                    let mut preprocessor_cmd = Command::new("cpp")
                        .arg("-xassembler-with-cpp")
                        .args(
                            opts.isystem
                                .iter()
                                .map(|path| osjoin("-isystem", path.as_os_str())),
                        )
                        .args(
                            opts.include
                                .iter()
                                .map(|path| osjoin("-include", path.as_os_str())),
                        )
                        .arg("-nostdinc")
                        .arg("-E")
                        .arg(file.as_os_str())
                        // If no output file specified it just gets put on stdout, so we can use that to
                        // just dump straight into dtc, which accepts input from stdout
                        .stdout(Stdio::piped())
                        .spawn()
                        .unwrap_or_else(|e| fail_with_err("Failed to execute preprocessor", e));

                    let preprocessor_stdout = preprocessor_cmd.stdout.take().unwrap_or_else(|| {
                        eprintln!("Failed to open preprocessor stdout");
                        exit(-1);
                    });

                    let out = Command::new("dtc")
                        .current_dir(file.parent().unwrap())
                        .arg("-Idts")
                        .arg("-Odtb")
                        .stdin(Stdio::from(preprocessor_stdout))
                        .output()
                        .unwrap_or_else(|e| fail_with_err("Failed to run dtc", e));

                    if preprocessor_cmd.wait().is_err()
                        || preprocessor_cmd
                            .wait()
                            .is_ok_and(|status| !status.success())
                    {
                        // TODO:
                        // This is actually super likely so fix it
                        eprintln!("Preprocessor command failed :)");
                        // Equivalent to continue since we are in a filter_map
                        return None;
                    }
                    if !out.status.success() {
                        eprintln!("dtc exited with non-zero exit code: {}", out.status);
                        eprintln!(
                            "
                            Here was its stderr: \n{}",
                            String::from_utf8_lossy(&out.stderr)
                        );
                        eprintln!(
                            "Here was its stdout: \n{}",
                            String::from_utf8_lossy(&out.stderr)
                        );
                        // Equivalent to continue since we are in a filter_map
                        return None;
                    }

                    // At this point we have succesfully compiled a file, and the binary is on stdout
                    Some(out.stdout.into_boxed_slice())
                }
                DTreeType::Dtb => match fs::read(file) {
                    Ok(data) => Some(data.into_boxed_slice()),
                    Err(e) => {
                        eprintln!("Failed to read dtb. Err: {e}");
                        None
                    }
                },
            }
        })
        .collect();

    let final_good_dtb_count = compiled_devtrees.len();

    let final_fail_count = final_found_count - final_good_dtb_count;

    meta_stats.found = final_found_count;
    meta_stats.compiled = final_good_dtb_count;

    eprintln!();
    eprintln!(
        "Successfully compiled/found {final_good_dtb_count} dtbs ({final_fail_count} failed)"
    );

    compiled_devtrees
}

#[derive(Serialize)]
struct MetaStats {
    found: usize,
    compiled: usize,
    parsed: usize,
}

fn fail_with_err<E: std::error::Error>(msg: &str, error: E) -> ! {
    eprintln!("{msg}\n error: {error}");
    exit(-1);
}

#[derive(Parser)]
#[command(version, about, long_about=None)]
/// A command-line tool for recovering statistics about collections of device trees.
struct Cli {
    /// Path to the directory that will be recursively searched for .dts and .dtb files.
    #[arg(default_value = "./")]
    input_dir: PathBuf,

    /// zephyr project base directory as created with west init.
    /// If set, will automatically append zephyr's include paths to isystem.
    /// Assumes you have also run west update.
    #[arg(long)]
    zephyr_proj_dir: Option<PathBuf>,

    /// An arg to be directly passed to the c/dts preprocessor via -isystem.
    #[arg(long)]
    isystem: Vec<PathBuf>,

    /// An arg to be directly passed to the c/dts preprocessor via -include.
    #[arg(long)]
    include: Vec<PathBuf>,

    /// When specified, ignores .dts (syntax/textual) files and only collects stats on .dtb files.
    #[arg(long, conflicts_with = "no_dtb")]
    no_dts: bool,

    /// When specified, ignores .dtb (binary/flattened) files and only collects stats on .dts files.
    #[arg(long, conflicts_with = "no_dts")]
    no_dtb: bool,
}

#[cfg(test)]
mod tests {
    use std::process::{Command, ExitStatus};

    #[test]
    fn dtc_exists() {
        const MIN_DTC_VER: &str = "1.7.0";

        let out = Command::new("dtc")
            .args(["-v"])
            .output()
            .expect("dtc command not found");

        assert!(ExitStatus::success(&out.status), "dtc bad exit code");
        let stdout = std::str::from_utf8(out.stdout.as_slice()).unwrap();
        let semver = stdout
            .split(' ')
            .next_back()
            .expect("dtc bad output")
            .trim();

        let act_vers = semver.split('.').map(|n| n.parse::<usize>().unwrap());
        let exp_vers = MIN_DTC_VER.split('.').map(|n| n.parse::<usize>().unwrap());

        // Semver is >= expected
        for (expected, actual) in exp_vers.zip(act_vers) {
            match actual.cmp(&expected) {
                std::cmp::Ordering::Less => panic!(
                    "Installed DTC version: {semver} is less than expected version: {MIN_DTC_VER}"
                ),
                std::cmp::Ordering::Equal => continue,
                std::cmp::Ordering::Greater => break,
            }
        }
        println!("Installed DTC version {semver} >= {MIN_DTC_VER}");
    }
}
