#![feature(bench_black_box)]

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]
#[cfg(not(feature = "std"))]
use panic_halt as _;
#[cfg(not(feature = "std"))]
use cortex_m_rt::entry;
#[cfg(not(feature = "std"))]
use cortex_m_semihosting::hprintln;
#[cfg(not(feature = "std"))]
use stm32f4xx_hal as hal;
#[cfg(not(feature = "std"))]
use hal::{delay::Delay, pac, prelude::*};

use core::time::Duration;
#[cfg(feature = "std")]
use std::time::Instant;

//use benchmark_simple::*;
use generic_array::GenericArray;

/// Benchmark function signature.
type BenchFn = fn(&mut Data);

struct Data<'d> {
    /// Usually the cipher text.
    a: &'d mut [u8],
    /// Usually the plain text
    b: &'d mut [u8],
    key: &'d [u8],
}

#[cfg(not(feature = "std"))]
use cortex_m::peripheral::SYST;

struct Timer<'p> {
    #[cfg(feature = "std")]
    start: Instant,
    #[cfg(not(feature = "std"))]
    syst: &'p mut SYST,
}

impl<'p> Timer<'p> {
    #[cfg(feature = "std")]
    fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    #[cfg(not(feature = "std"))]
    fn new(mut syst: &'p mut SYST) -> Self {
        syst.enable_interrupt();
        Self {
            syst,
        }
    }

    fn start(&mut self) {
        #[cfg(feature = "std")]
        {
            self.start = Instant::now();
        }
        #[cfg(not(feature = "std"))]
        {
            self.syst.set_reload(0x00FFFFFF);
            self.syst.clear_current();
            self.syst.enable_counter()
        }
    }

    fn end(&mut self) -> Duration {
        #[cfg(feature = "std")]
        {
            self.start.elapsed()
        }
        #[cfg(not(feature = "std"))]
        {
            Duration::from_micros(SYST::get_current() as u64)
        }
    }
}

const ROUNDS: usize = 300;
const SAMPLE_COUNT: usize = 10;

#[cfg(feature = "std")]
type Periphs = ();
#[cfg(not(feature = "std"))]
type Periphs = (cortex_m::peripheral::Peripherals, pac::Peripherals);

/// Benchmarks the specified function, returning the median time to run `ROUNDS` of the function
fn benchmark<'p>(func: BenchFn, data: &mut Data, peripherals: &'p mut Periphs) -> Duration {
    let mut samples = [Duration::from_secs(0); SAMPLE_COUNT];

    #[cfg(feature = "std")]
    let mut timer = Timer::new();

    #[cfg(not(feature = "std"))]
    let mut timer = Timer::new(&mut peripherals.0.SYST);
    #[cfg(not(feature = "std"))]
    let b = unsafe { core::ptr::read(&mut peripherals.1.GPIOB).split() };
    #[cfg(not(feature = "std"))]
    let mut blue_led = b.pb14.into_push_pull_output();
    #[cfg(not(feature = "std"))]
    let mut green_led = b.pb15.into_push_pull_output();

    blue_led.set_low().ok();
    green_led.set_low().ok();
    for (sample_num, sample) in samples.iter_mut().enumerate() {
        let mut total = Duration::from_secs(0);
        for j in 0..ROUNDS {
            timer.start();
            func(data);
            let millis = timer.end();
            total += millis;
        }
        *sample = total;
        if sample_num == SAMPLE_COUNT / 16 {
            blue_led.set_high().ok();
            green_led.set_high().ok();
        }
    }
    introsort::sort(&mut samples);
    blue_led.set_high().ok();
    green_led.set_low().ok();

    //Return median
    samples[samples.len() / 2]
}

#[cfg_attr(not(feature = "std"), entry)]
fn main() -> ! {
    const TMP_LEN: usize = 1024;
    const KEY_LENGTH: usize = 1024;

    let mut buf = [0u8; TMP_LEN + TMP_LEN + KEY_LENGTH];
    for (i, value) in buf.iter_mut().enumerate() {
        //TODO: Randomly generate
        *value = i as u8;
    }
    let (a, rest) = buf.split_at_mut(TMP_LEN);
    let (b, key) = rest.split_at_mut(TMP_LEN); 

    let mut data = Data { a, b, key };
    core::hint::black_box(&mut data);

    let functions: [(BenchFn, &'static str); 4] = [
        ////(test_aes_128, "AES-128"),
        ////(test_aes_192, "AES-192"),
        ////(test_aes_256, "AES-256"),
        ////(test_blowfish, "Blowfish"),
        //(test_cast5, "Cast5"),
        ////(test_des, "DES"),
        ////(test_3des, "Triple DES"),
        //(test_idea, "Idea"),
        ////(test_kuznyechik, "Kuznyechik"),
        (test_rc2, "Rc2"),//7.59s, 7.59, 22.92
        //(test_serpent, "Serpent"),//VERY SLOW
        (test_sm4, "Sm4"),//7.08, 7.06, 21.16
        //(test_twofish, "Twofish"),
        //(test_threefish256, "Threefish-256"),//49.73
        //(test_threefish512, "Threefish-512"),//46.69
        //(test_threefish1024, "Threefish-1024"),//47.96
        (test_xor, "Xor"),//0.??, 0.3, 0.62
        (test_xxtea, "XXTEA"),//6.35, 6.30, 19.28
    ];

    #[cfg(feature = "std")]
    let peripherals = ();
    #[cfg(not(feature = "std"))]
    let mut peripherals = (cortex_m::peripheral::Peripherals::take().unwrap(), pac::Peripherals::take().unwrap());
    for (func, name) in functions {
        let median = benchmark(func, &mut data, &mut peripherals);
        let bytes_per_iteration = TMP_LEN * ROUNDS;
        let mut bytes_per_sec = bytes_per_iteration as f32 / median.as_secs_f32();
        //func(&mut data);
        //let res = bench.run(&options, || );
        //let throughput = res.throughput(data.a.len() as _);
        let digits = ["", "K", "M", "G", "T"];
        let mut digit = 0;
        while bytes_per_sec > 1000.0 {
            bytes_per_sec /= 1000.0;
            digit += 1;
        }
        
        //Swap the slices, so that we re-encrypt data for each algorithm
        //This stops the optimizer from realizing that encrypting to the same buffer that gets
        //overridden has no side effects
        core::mem::swap(&mut data.a, &mut data.b);

        #[cfg(feature = "std")]
        {
            println!("{} {:.2} {}B/s", name, bytes_per_sec, digits[digit]);
        }
        #[cfg(not(feature = "std"))]
        {
            //hprintln!("{} {:.2} {}B/s", name, bytes_per_sec, digits[digit]).unwrap();
        }
    }
    #[cfg(feature = "std")]
    {
        std::process::exit(0);
    }
    #[cfg(not(feature = "std"))]
    {
        loop {}
    }
}

fn test_block_encrypt<T>(data: &mut Data, cipher: T, block_size: usize)
where
    T: cipher::BlockEncrypt,
{
    // Ciphertext size must be a multiple of the block size
    debug_assert!(data.a.len() % block_size == 0);
    let mut offset = 0;
    while offset < data.a.len() {
        let block = GenericArray::from_mut_slice(&mut data.a[offset..offset + block_size]);
        cipher.encrypt_block(block);
        offset += block_size;
    }
    //"use" `a` to prevent optimization
    core::hint::black_box(&mut data.a);
}

macro_rules! encrypt {
    ($func_name:ident, $cipher_path:path, $block_size:literal, $key_size:literal) => {
        fn $func_name(data: &mut Data) {
            use $cipher_path as Path;
            let key = &data.key[..$key_size];
            let cipher = Path::new(generic_array::GenericArray::from_slice(key));
            test_block_encrypt(data, cipher, $block_size);
        }
    };
}

use cipher::NewBlockCipher;
encrypt!(test_aes_128, aes::Aes128, 16, 16);
encrypt!(test_aes_192, aes::Aes192, 16, 24);
encrypt!(test_aes_256, aes::Aes256, 16, 32);
encrypt!(test_blowfish, blowfish::BlowfishLE, 8, 56);
encrypt!(test_cast5, cast5::Cast5, 8, 16);
encrypt!(test_des, des::Des, 8, 8);
encrypt!(test_3des, des::TdesEee3, 8, 24);
encrypt!(test_idea, idea::Idea, 8, 16);
encrypt!(test_kuznyechik, kuznyechik::Kuznyechik, 16, 32);
//encrypt!(test_magma, magma::Gost89, 16);
encrypt!(test_rc2, rc2::Rc2, 8, 32);
encrypt!(test_serpent, serpent::Serpent, 16, 16);
encrypt!(test_sm4, sm4::Sm4, 16, 16);
encrypt!(test_twofish, twofish::Twofish, 16, 32);
encrypt!(test_threefish256, threefish::Threefish256, 32, 32);
encrypt!(test_threefish512, threefish::Threefish512, 64, 64);
encrypt!(test_threefish1024, threefish::Threefish1024, 128, 128);

fn test_xor(data: &mut Data) {
    const USIZE_SIZE: usize = core::mem::size_of::<usize>();
    assert!(data.a.len() % USIZE_SIZE == 0);
    assert!(data.key.len() % USIZE_SIZE == 0);

    let words = unsafe {
        core::slice::from_raw_parts_mut(data.a.as_mut_ptr() as *mut usize, data.a.len() / USIZE_SIZE)
    };
    let key = unsafe {
        core::slice::from_raw_parts(
            data.key.as_ptr() as *const usize,
            data.key.len() / USIZE_SIZE,
        )
    };
    for (val, key) in words.iter_mut().zip(key.iter()) {
        *val ^= key;
    }
    core::hint::black_box(&mut data.a);
}

fn test_xxtea(data: &mut Data) {
    xxtea::encrypt(data.a, &data.key[..16]);
    core::hint::black_box(&mut data.a);
}
