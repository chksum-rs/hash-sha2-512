#![no_main]

use chksum_hash_sha2_512 as sha2_512;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sha2_512::hash(data);
});
