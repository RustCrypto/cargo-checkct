//! End-to-end tests, which require binsec.

use std::sync::{Mutex, MutexGuard};

mod common;
use common::{cargo_checkct, edit_driver, fixture, init};

/// Each test already builds and verifies drivers in parallel, so run them one at a time
/// to avoid exhausting the memory of the machine.
fn serialize() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn run(lib: &std::path::Path, args: &[&str]) -> (bool, String) {
    let output = cargo_checkct()
        .arg("run")
        .arg("--dir")
        .arg(lib)
        .arg("--timeout=60")
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    println!("{stdout}");
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    (output.status.success(), stdout)
}

#[test]
fn subtle() {
    let _guard = serialize();
    let (_tmp, lib) = fixture("subtle_eq");
    init(
        &lib,
        r#"use subtle_eq::ConstantTimeEq;
    let mut left = [0u8; 8];
    let mut right = [0x42u8; 8];
    PrivateRng.fill_bytes(&mut left);
    PublicRng.fill_bytes(&mut right);
    core::hint::black_box(left.ct_eq(&right));
    // Large enough to be zeroed by memset, which uses `rep stos` on x86_64
    let mut buffer = [0u8; 4096];
    core::hint::black_box(&mut buffer);"#,
    );

    let (success, stdout) = run(&lib, &[]);
    assert!(success);
    assert!(stdout.contains("SECURE"));
    assert!(!stdout.contains("INSECURE"));
}

#[test]
fn vulnerable() {
    let _guard = serialize();
    let (_tmp, lib) = fixture("vulnerable_eq");
    init(
        &lib,
        r#"use vulnerable_eq::eq;
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    PrivateRng.fill_bytes(&mut left);
    PublicRng.fill_bytes(&mut right);
    core::hint::black_box(eq(&left, &right));"#,
    );
    // A second, secure, entrypoint in the same driver, with a panic path that only depends on
    // public values
    edit_driver(&lib, "driver", |driver| {
        driver
            + r#"
#[checkct]
pub fn checkct_xor() {
    assert!(PublicRng.next_u32() != 0);
    core::hint::black_box(PrivateRng.next_u64() ^ PublicRng.next_u64());
}
"#
    });

    let (success, stdout) = run(&lib, &[]);
    assert!(!success);
    assert!(stdout.contains("INSECURE"));
    let summary = stdout.split("Summary:").nth(1).unwrap();
    for target in [
        "thumbv7em-none-eabihf",
        "riscv32imac-unknown-none-elf",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
    ] {
        let entrypoint_status = |entrypoint: &str| {
            summary
                .lines()
                .find(|line| line.contains(target) && line.contains(entrypoint))
                .and_then(|line| line.split_whitespace().last())
                .map(str::to_owned)
        };
        assert_eq!(
            entrypoint_status("driver::driver::checkct ").as_deref(),
            Some("insecure"),
            "{target}"
        );
        assert_eq!(
            entrypoint_status("driver::driver::checkct_xor").as_deref(),
            Some("secure"),
            "{target}"
        );
    }
}

#[test]
fn secret_division() {
    let _guard = serialize();
    let (_tmp, lib) = fixture("secret_division");
    init(
        &lib,
        r#"core::hint::black_box(secret_division::div(PublicRng.next_u32(), PrivateRng.next_u32()));"#,
    );

    // Divisions are not checked by default
    let (success, stdout) = run(&lib, &[]);
    assert!(success);
    assert!(!stdout.contains("INSECURE"));

    let (success, stdout) = run(&lib, &["--checks=control-flow,memory-access,divisor"]);
    assert!(!success);
    assert!(stdout.contains("INSECURE"));
}

#[test]
fn aarch64() {
    let _guard = serialize();
    let (_tmp, lib) = fixture("secret_division");
    init(
        &lib,
        r#"assert!(PublicRng.next_u64() != 0);
    core::hint::black_box(PrivateRng.next_u64() ^ PublicRng.next_u64());"#,
    );
    // Exercise both supported ELF targets. The bare-metal target uses rust-lld by default.
    let config_path = lib.join("checkct/.cargo/config.toml");
    let mut config: toml::Table = std::fs::read_to_string(&config_path)
        .unwrap()
        .parse()
        .unwrap();
    config["build"]["target"] = toml::Value::Array(
        ["aarch64-unknown-linux-gnu", "aarch64-unknown-none"]
            .into_iter()
            .map(|target| toml::Value::String(target.to_owned()))
            .collect(),
    );
    std::fs::write(config_path, toml::to_string(&config).unwrap()).unwrap();
    edit_driver(&lib, "driver", |driver| {
        driver
            + r#"
#[checkct]
pub fn secret_select() {
    let selected: u64;
    unsafe {
        core::arch::asm!(
            "cmp {secret}, #0",
            "csel {selected}, {secret}, xzr, ne",
            secret = in(reg) PrivateRng.next_u64(),
            selected = lateout(reg) selected,
            options(nomem, nostack),
        );
    }
    core::hint::black_box(selected);
}

#[checkct]
pub fn secret_branch() {
    // Force a branch so LLVM cannot replace the positive control with a select.
    unsafe {
        core::arch::asm!(
            "cbz {secret}, 2f",
            "nop",
            "2:",
            secret = in(reg) PrivateRng.next_u64(),
            options(nomem, nostack),
        );
    }
}

#[checkct]
pub fn secret_address() {
    let table = core::hint::black_box([0u8; 16]);
    let index = (PrivateRng.next_u64() & 15) as usize;
    // The index is in bounds and the volatile read preserves the memory access.
    core::hint::black_box(unsafe { table.as_ptr().add(index).read_volatile() });
}

#[checkct]
pub fn secret_divisor() {
    let divisor = PrivateRng.next_u64() | 1;
    core::hint::black_box(PublicRng.next_u64() / divisor);
}
"#
    });

    for (args, division_status) in [
        (Vec::new(), "secure"),
        (
            vec!["--checks=control-flow,memory-access,divisor"],
            "insecure",
        ),
    ] {
        let (success, stdout) = run(&lib, &args);
        assert!(!success);
        let summary = stdout.split("Summary:").nth(1).unwrap();
        for target in ["aarch64-unknown-linux-gnu", "aarch64-unknown-none"] {
            for (entrypoint, expected) in [
                ("driver::driver::checkct", "secure"),
                ("driver::driver::secret_select", "secure"),
                ("driver::driver::secret_branch", "insecure"),
                ("driver::driver::secret_address", "insecure"),
                ("driver::driver::secret_divisor", division_status),
            ] {
                let status = summary.lines().find_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    (fields.get(1) == Some(&target) && fields.get(2) == Some(&entrypoint))
                        .then(|| fields.get(3).copied())
                        .flatten()
                });
                assert_eq!(status, Some(expected), "{target} {entrypoint}");
            }
        }
    }
}
