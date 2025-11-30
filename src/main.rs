use std::{
    mem::MaybeUninit,
    time::{self, Duration},
};

use anyhow::anyhow;
use bpf::interface::Aggregate;
use clap::Parser;
use libbpf_rs::{
    ErrorExt, MapCore, MapFlags,
    skel::{OpenSkel as _, Skel, SkelBuilder as _},
};
use zerocopy::FromBytes as _;

mod bpf;

#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pid: i32,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut skel_builder = bpf::sched_events::SchedEventsSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let mut open_obj = MaybeUninit::uninit();
    let mut open_skel = skel_builder
        .open(&mut open_obj)
        .context("opening bpf obj")?;

    let rodata = open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .ok_or(anyhow!("Cannot find rodata section"))?;

    /* It may be useful to distinguish between
     * tracking the full process or just a single thread. */
    rodata.args.target_tgid = args.pid;

    let skel = open_skel.load().context("loading skeleton")?;
    let link = skel
        .progs
        .handle__sched_switch
        .attach()
        .context("attaching program");

    std::thread::sleep(Duration::from_secs(10));

    drop(link);

    loop {
        let entries = skel.maps.aggregates.lookup_and_delete_batch(
            4096,
            MapFlags::empty(),
            MapFlags::empty(),
        )?;

        let mut found_any = false;
        for entry in entries {
            found_any = true;

            Aggregate::read_from_bytes(&entry.1[..]).unwrap();
        }

        if !found_any {
            break;
        }
    }

    Ok(())
}
