use std::arch::x86_64::_rdtsc;
use std::clone::Clone;
use std::cmp::min;
use std::fmt::Debug;
use std::vec::Drain;
//use separator::Separatable;

/*
pub fn duration_to_millis(dur: &Duration) -> u64 {
    dur.as_secs() * 1000 + (dur.subsec_nanos() / 1000000) as u64
}

pub fn duration_to_micros(dur: &Duration) -> u64 {
    dur.as_secs() * 1000 * 1000 + (dur.subsec_nanos() / 1000) as u64
}

*/

pub struct TimerWheel<T>
where
    T: Clone,
{
    resolution_cycles: u64,
    no_slots: usize,
    last_slot: usize,  // slot which was drained at the last tick
    last_advance: u64, // number of slots drained since start
    start: u64,        // time when wheel started
    slots: Vec<Vec<T>>,
}

#[allow(dead_code)]
impl<T> TimerWheel<T>
where
    T: Clone,
{
    pub fn new(no_slots: usize, resolution_cycles: u64, slot_capacity: usize) -> TimerWheel<T> {
        //let now = utils::rdtsc_unsafe();
        //println!("wheel start = {:?}", now);
        TimerWheel {
            resolution_cycles,
            no_slots,
            last_slot: no_slots - 1,
            last_advance: 0,
            start: 0,
            slots: vec![Vec::with_capacity(slot_capacity); no_slots],
        }
    }

    #[inline]
    pub fn resolution(&self) -> u64 {
        self.resolution_cycles
    }

    #[inline]
    pub fn get_max_timeout_cycles(&self) -> u64 {
        (self.no_slots as u64 - 1) * self.resolution_cycles as u64
    }

    pub fn tick(&mut self, now: &u64) -> (Option<Drain<T>>, bool) {
        if self.start != 0 {
            // only when the wheel has been started
            let dur = *now - self.start;
            let advance = dur / self.resolution_cycles;
            //trace!("dur= {:?}, advance= {}, last_advance= {}", dur, advance, self.last_advance);
            let progress = (advance - self.last_advance) as usize;
            let mut slots_to_process = min(progress, self.no_slots);
            if progress > self.no_slots {
                self.last_slot = (advance - slots_to_process as u64).wrapping_rem(self.no_slots as u64) as usize;
                self.last_advance = advance - slots_to_process as u64;
            }
            while slots_to_process > 0 {
                self.last_slot = (self.last_slot + 1).wrapping_rem(self.no_slots);
                self.last_advance += 1;
                if self.slots[self.last_slot].len() > 0 {
                    debug!(
                        "slots_to_process= {}, processing slot {} with {} events",
                        slots_to_process,
                        self.last_slot,
                        self.slots[self.last_slot].len()
                    );
                    return (Some(self.slots[self.last_slot].drain(..)), slots_to_process > 1);
                } else {
                    slots_to_process -= 1
                }
            }
        }
        (None, false)
    }

    /// schedules a new element and returns the slot and the index in the wheel
    pub fn schedule(&mut self, after_cycles: &u64, what: T) -> (u16, u16)
    where
        T: Debug,
    {
        let now = unsafe { _rdtsc() };
        //initialize start time
        if self.start == 0 {
            self.start = now - self.resolution_cycles;
        }
        let dur = *after_cycles + now - self.start;
        let slots = dur / self.resolution_cycles - 1;
        let slot = slots.wrapping_rem(self.no_slots as u64);
        debug!(
            "scheduling port {:?} at {:?} in slot {}",
            what,
            self.slots[slot as usize].len(),
            slot
        );
        self.slots[slot as usize].push(what);
        (slot as u16, (self.slots[slot as usize].len() - 1) as u16)
    }

    // we use replace to remove elements from the wheel by overwriting them with an invalid value
    #[inline]
    pub fn replace(&mut self, slot_and_index: (u16, u16), new_element: T) -> Option<T> {
        let slot = slot_and_index.0 as usize;
        let index = slot_and_index.1 as usize;
        debug!("replace: slot = {}, index = {}", slot, index);
        if index < self.slots[slot].len() {
            let old = self.slots[slot][index].clone();
            self.slots[slot][index] = new_element;
            Some(old)
        } else {
            None
        }
    }
}

#[cfg(test)]
// run this test with --release flag, it is real-time sensitive
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;
    use super::super::system::SystemData;

    #[test]
    fn event_timing() {
        let system_data = SystemData::detect();
        let milli_to_cycles: u64 = system_data.cpu_clock / 1000;

        let start = unsafe { _rdtsc() };
        println!("start = {:?}", start);

        let mut wheel: TimerWheel<u16> = TimerWheel::new(128, 16 * milli_to_cycles, 128);

        for j in 0..128 {
            let n_millis: u16 = j * 16 + 8;
            let _slot = wheel.schedule(&((n_millis as u64) * milli_to_cycles), n_millis);
            //println!("n_millis= {}, slot = {}", n_millis, _slot);
        }

        let mut n_found = 0;
        for _i in 0..1024 {
            // proceed with roughly 2 ms ticks
            thread::sleep(Duration::from_millis(2));
            let now = unsafe { _rdtsc() };
            match wheel.tick(&now) {
                (Some(mut drain), _more) => {
                    let event = drain.next();
                    if event.is_some() {
                        assert_eq!(&(now - start) / 16 / milli_to_cycles, (event.unwrap() / 16) as u64);
                        n_found += 1;
                    } else {
                        assert!(false);
                    }; // there must be one event in each slot
                }
                (None, _more) => (),
            }
        }
        assert_eq!(n_found, 128);

        // test that wheel overflow does not break the code:
        wheel.schedule(&((5000 as u64) * milli_to_cycles), 5000);

        let mut found_it: bool = false;
        for _i in 0..1024 {
            // proceed with roughly 2 ms ticks
            thread::sleep(Duration::from_millis(2));
            let now = unsafe { _rdtsc() };
            match wheel.tick(&now) {
                (Some(mut drain), _more) => {
                    let event = drain.next();
                    if event.is_some() {
                        assert_eq!(5000, event.unwrap() as u64);
                        found_it = true;
                    }
                }
                (None, _more) => (),
            }
        }
        assert!(found_it);
    }

    #[test]
    fn replace_element_in_timer_wheel() {
        let system_data = SystemData::detect();
        let milli_to_cycles: u64 = system_data.cpu_clock / 1000;

        let mut wheel: TimerWheel<u16> = TimerWheel::new(128, 16 * milli_to_cycles, 128);
        // populate
        for j in 0..128 {
            let n_millis: u16 = j * 16 + 8;
            let _slot = wheel.schedule(&((n_millis as u64) * milli_to_cycles), n_millis);
            //println!("n_millis= {}, slot = {}", n_millis, _slot);
        }
        // add the test element
        let n_millis = 100;
        let slot_and_index = wheel.schedule(&((n_millis as u64) * milli_to_cycles), n_millis);
        let old = wheel.replace(slot_and_index, 101);
        assert_eq!(old.unwrap(), n_millis);
    }
}
