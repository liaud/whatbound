use std::{
    collections::HashMap,
    mem::MaybeUninit,
    ops::{Add, AddAssign},
    time::Duration,
};

use anyhow::anyhow;
use bpf::interface::Aggregate;
use clap::Parser;
use libbpf_rs::{
    ErrorExt, MapCore, MapFlags,
    skel::{OpenSkel as _, SkelBuilder as _},
};
use zerocopy::FromBytes as _;

mod bpf;

#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pid: i32,

    #[arg(short, long)]
    verbose: bool,

    #[arg(short, long)]
    timeout_s: f64,

    #[arg(long)]
    obj_build_debug: bool,
}

#[derive(Debug, Default, Copy, Clone)]
struct GroupAggregate {
    total_running: Duration,
    total_waiting: Duration,
    total_sleeping: Duration,
}

impl Add<GroupAggregate> for GroupAggregate {
    type Output = Self;

    fn add(self, rhs: GroupAggregate) -> Self::Output {
        Self {
            total_running: self.total_running + rhs.total_running,
            total_waiting: self.total_waiting + rhs.total_waiting,
            total_sleeping: self.total_sleeping + rhs.total_sleeping,
        }
    }
}

impl AddAssign<GroupAggregate> for GroupAggregate {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut skel_builder = bpf::sched_events::SchedEventsSkelBuilder::default();
    skel_builder.obj_builder.debug(args.obj_build_debug);

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
    rodata.args.verbose.write(args.verbose);

    let skel = open_skel.load().context("loading skeleton")?;
    let link = skel
        .progs
        .handle__sched_switch
        .attach()
        .context("attaching program");

    std::thread::sleep(Duration::from_secs_f64(args.timeout_s));

    drop(link);

    println!("kind\tunit\tname\ttotal_accounted\trunning\twaiting\tsleeping");
    let mut groups: HashMap<String, GroupAggregate> = HashMap::new();
    loop {
        let entries = skel.maps.aggregates.lookup_and_delete_batch(
            4096,
            MapFlags::empty(),
            MapFlags::empty(),
        )?;

        let mut found_any = false;

        for entry in entries {
            found_any = true;

            let agg = Aggregate::read_from_bytes(&entry.1[..]).unwrap();
            let total_running = Duration::from_nanos(agg.total_running);
            let total_waiting = Duration::from_nanos(agg.total_waiting);
            let total_sleeping = Duration::from_nanos(agg.total_sleeping);
            let total_accounted = total_running + total_waiting + total_sleeping;
            let name = str::from_utf8(&agg.comm[..])
                .unwrap()
                .trim_matches(char::from(0))
                .replace(" ", "_");

            println!(
                "entry\ts\t{}\t{:.06}\t{:.06}\t{:.06}\t{:.06}",
                name,
                total_accounted.as_secs_f64(),
                total_running.as_secs_f64(),
                total_waiting.as_secs_f64(),
                total_sleeping.as_secs_f64(),
            );

            let group_key = name.trim_matches(char::is_numeric).to_string();
            *groups.entry(group_key).or_default() += GroupAggregate {
                total_running,
                total_sleeping,
                total_waiting,
            };
        }

        if !found_any {
            break;
        }
    }

    for (group_name, group) in groups {
        let total_accounted = group.total_running + group.total_waiting + group.total_sleeping;

        println!(
            "aggregate\ts\t{}\t{:.06}\t{:.06}\t{:.06}\t{:.06}",
            group_name,
            total_accounted.as_secs_f64(),
            group.total_running.as_secs_f64(),
            group.total_waiting.as_secs_f64(),
            group.total_sleeping.as_secs_f64(),
        );
    }

    Ok(())
}
