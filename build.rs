use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsStr};

const SRC: &str = "src/bpf/sched_events.bpf.c";

fn main() {
    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ])
        .build_and_generate("src/bpf/sched_events.rs")
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
