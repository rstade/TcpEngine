use std::arch::x86_64::__cpuid;
use std::fs::File;
use std::io::Read;
use macaddr::{MacAddr6 as MacAddress, ParseError};
use std::path::Path;

const CPU_CLOCK_PATH: &str = "/sys/devices/system/cpu/cpu0/cpufreq/base_frequency";
pub fn get_tsc_frequency() -> Option<u64> {
    unsafe {
        // CPUID Leaf 0x15: TSC/Crystal Clock Information
        let result = __cpuid(0x15);

        if result.ebx == 0 || result.eax == 0 {
            return None;
        }

        // TSC frequency = (crystal_freq * ebx) / eax
        let crystal_freq = result.ecx; // in Hz
        let tsc_freq = (crystal_freq as u64 * result.ebx as u64) / result.eax as u64;

        Some(tsc_freq)
    }
}

#[derive(Clone)]
pub struct SystemData {
    pub tsc_frequency: u64, // base clock for rdtsc in Hz
}

impl SystemData {
    pub fn detect() -> SystemData {
        let tsc_freq = get_tsc_frequency();

        SystemData {
            tsc_frequency: tsc_freq.unwrap_or({
                                              let mut khz = String::new();
                                              File::open(CPU_CLOCK_PATH)
                                                  .and_then(|mut f| f.read_to_string(&mut khz))
                                                  .expect(&format!("cannot read {}", CPU_CLOCK_PATH));
                                               khz.pop(); // remove CR/LF
                                              khz.parse::<u64>().unwrap() * 1000}
            )
        }
    }
}

pub fn get_mac_from_ifname(ifname: &str) -> Result<MacAddress, ParseError> {
    let iface = Path::new("/sys/class/net").join(ifname).join("address");
    let mut macaddr = String::new();
    File::open(iface).and_then(|mut f| f.read_to_string(&mut macaddr)).unwrap();
    macaddr.lines().next().unwrap_or("").parse::<MacAddress>()
}

pub fn get_mac_string_from_ifname(ifname: &str) -> Result<String, ParseError> {
    let iface = Path::new("/sys/class/net").join(ifname).join("address");
    let mut macaddr = String::new();
    File::open(iface)
        .and_then(|mut f| f.read_to_string(&mut macaddr).map_err(|e| e.into()))
        .unwrap();
    Ok(macaddr.lines().next().unwrap_or("").to_string())
}
