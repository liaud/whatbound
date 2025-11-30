pub mod sched_events;

pub mod interface {
    use zerocopy_derive::FromBytes;

    #[derive(Debug, Default, Copy, Clone, FromBytes)]
    #[repr(C)]
    pub struct Aggregate {
        pub comm: [u8; 16],
        pub total_running: u64,
        pub total_waiting: u64,
        pub total_sleeping: u64,
    }

    #[cfg(test)]
    mod tests {
        use std::mem::{offset_of, size_of};

        macro_rules! assert_and_size_offsets {
            ($a:ty, $b:ty, $($attr:ident),+) => {
                assert!(size_of::<$a>() == size_of::<$b>());
                $(
                    assert!(
                        offset_of!($a, $attr)
                            == offset_of!($b, $attr)
                    );
                )+
            };
        }

        #[test]
        fn check_aggregate() {
            use crate::bpf::interface::Aggregate;
            use crate::bpf::sched_events::types::aggregate;

            const {
                assert_and_size_offsets!(
                    Aggregate,
                    aggregate,
                    comm,
                    total_running,
                    total_waiting,
                    total_sleeping
                );
            }
        }
    }
}
