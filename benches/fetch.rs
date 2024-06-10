use std::{net::IpAddr, sync::Arc, time::Duration};

use divan::black_box_drop;
use ipqs_db_reader::{FileReader, MemoryReader};
use rand::RngCore;

fn main() {
    divan::main();
}

#[inline]
fn random_ipv4(rng: &mut impl RngCore) -> IpAddr {
    let mut ip = [0u8; 4];
    rng.fill_bytes(&mut ip);
    IpAddr::from(ip)
}

#[divan::bench(min_time = Duration::from_secs(5), skip_ext_time)]
fn file_reader(bencher: divan::Bencher) {
    let path = std::path::Path::new("resources/ipv4.ipqs");
    let mut db = FileReader::open(path).expect("failed to open file");
    let mut rng = rand::thread_rng();
    bencher
        .with_inputs(|| random_ipv4(&mut rng))
        .bench_local_values(move |ip| black_box_drop(db.fetch(&ip)));
}

#[divan::bench(min_time = Duration::from_secs(5))]
fn memory_reader(bencher: divan::Bencher) {
    let path = std::path::Path::new("resources/ipv4.ipqs");
    let db = MemoryReader::open(path).expect("failed to open file");
    let mut rng = rand::thread_rng();
    bencher
        .with_inputs(|| random_ipv4(&mut rng))
        .bench_local_values(move |ip| black_box_drop(db.fetch(&ip)));
}

#[divan::bench(min_time = Duration::from_secs(5))]
fn memory_reader_arc(bencher: divan::Bencher) {
    let path = std::path::Path::new("resources/ipv4.ipqs");
    let db = Arc::new(MemoryReader::open(path).expect("failed to open file"));
    let mut rng = rand::thread_rng();
    bencher
        .with_inputs(|| random_ipv4(&mut rng))
        .bench_local_values(move |ip| {
            let arc_record = db.arc_fetch(&ip)?;
            let record = arc_record.as_record();
            black_box_drop(record);
            black_box_drop(arc_record);
            Ok::<(), Box<dyn std::error::Error>>(())
        });
}
