use std::{net::IpAddr, time::Duration};

use divan::black_box_drop;
use ipqs_db_reader::file_reader;
use rand::RngCore;

fn main() {
    divan::main();
}

#[divan::bench(min_time = Duration::from_secs(5), skip_ext_time)]
fn file_reader(bencher: divan::Bencher) {
    let path = std::path::Path::new("resources/ipv4.ipqs");
    let mut db = file_reader::FileReader::open(path).expect("failed to open file");
    let mut rng = rand::thread_rng();
    bencher
        .with_inputs(|| {
            let mut ip = [0u8; 4];
            rng.fill_bytes(&mut ip);
            IpAddr::from(ip)
        })
        .bench_local_values(move |ip| black_box_drop(db.fetch(&ip)));
}
