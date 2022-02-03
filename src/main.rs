#![feature(bench_black_box)]
#![no_std]
use benchmark_simple::*;
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

fn main() {
    const TMP_LEN: usize = 1024 *  16;
    const KEY_LENGTH: usize = 1024 * 16;

    let mut buf = [0u8; TMP_LEN + TMP_LEN + KEY_LENGTH];
    for (i, value) in buf.iter_mut().enumerate() {
        //TODO: Randomly generate
        *value = core::hint::black_box(i as u8);
    }
    let (a, rest) = buf.split_at_mut(TMP_LEN);
    let (b, key) = rest.split_at_mut(TMP_LEN);

    let bench = Bench::new();
    let options = Options {
        iterations: 50,
        warmup_iterations: 5,
        min_samples: 25,
        max_samples: 10000,
        max_rsd: 5.0,
        max_duration: None,
        verbose: false,
    };

    let mut data = Data { a, b, key };
    core::hint::black_box(&mut data);

    let functions: [(BenchFn, &'static str); 18] = [
        (test_aes_128, "AES-128"),
        (test_aes_192, "AES-192"),
        (test_aes_256, "AES-256"),
        (test_blowfish, "Blowfish"),
        (test_cast5, "Cast5"),
        (test_des, "DES"),
        (test_3des, "Triple DES"),
        (test_idea, "Idea"),
        (test_kuznyechik, "Kuznyechik"),
        (test_rc2, "Rc2"),
        (test_serpent, "Serpent"),
        (test_sm4, "Sm4"),
        (test_twofish, "Twofish"),
        (test_threefish256, "Threefish-256"),
        (test_threefish512, "Threefish-512"),
        (test_threefish1024, "Threefish-1024"),
        (test_xor, "Xor"),
        (test_xxtea, "XXTEA"),
    ];

    for (func, name) in functions {
        let res = bench.run(&options, || func(&mut data));
        let throughput = res.throughput(data.a.len() as _);
        //Swap the slices, so that we re-encrypt data for each algorithm
        //This stops the optimizer from realizing that encrypting to the same buffer that gets
        //overridden has no side effects
        core::mem::swap(&mut data.a, &mut data.b);
        //println!("{} throughput: {}", name, throughput);
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
