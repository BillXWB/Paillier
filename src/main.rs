use std::io;
use std::io::Write;

use log::{debug, info};
use num::{Integer, Zero};
use num_bigint::BigUint;
use rand::thread_rng;

use paillier::{PrivateKey, PublicKey};

pub fn input(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut line = String::default();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn main() -> io::Result<()> {
    env_logger::init();
    let m: u32 = match input("竞选人数：")?.parse().ok() {
        Some(m) if m > 0 => m,
        _ => panic!("非法人数"),
    };
    let n: u32 = match input("投票人数：")?.parse().ok() {
        Some(n) if 0 < n && n < u32::MAX => n,
        _ => panic!("非法人数"),
    };
    let key_length =
        usize::checked_mul(m as _, (u32::BITS - (n + 1).leading_zeros()) as _).expect("人数过多");
    let encode = |x: u32| -> BigUint { BigUint::from(n + 1).pow(x - 1) };
    info!("生成密钥中...");
    let private_key = PrivateKey::new(key_length, &mut thread_rng());
    let public_key = PublicKey::new(&private_key);
    let result = BigUint::zero();
    let mut result = public_key.encrypt(&result, &mut thread_rng()).unwrap();
    for i in 1..=n {
        let x: u32 = match input(&format!("{} 号投票：", i))?.parse().ok() {
            Some(x) if 1 <= x && x <= m => x,
            _ => panic!("非法选票"),
        };
        let x = encode(x);
        let r = private_key.decrypt(&result).unwrap();
        debug!("明文相加：{} + {} = {}", r, x, &r + &x);
        let x = public_key.encrypt(&x, &mut thread_rng()).unwrap();
        result = public_key.add_encrypted(&result, &x).unwrap();
    }
    let mut result = private_key.decrypt(&result).unwrap();
    println!("投票结果：");
    for i in 1..=m {
        let (q, r) = result.div_rem(&BigUint::from(n + 1));
        println!("{} 号票数：{}", i, r);
        result = q;
    }
    Ok(())
}
