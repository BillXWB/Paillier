// https://en.wikipedia.org/wiki/Paillier_cryptosystem

use log::{debug, trace};
use num::{Integer, One, Zero};
use num_bigint::BigUint;
use num_bigint::RandBigInt;
use num_modular::ModularUnaryOps;
use num_prime::RandPrime;
use rand::{CryptoRng, Rng};

pub struct PrivateKey {
    n: BigUint,
    n_2: BigUint,
    lambda: BigUint, // phi(n)
    mu: BigUint,     // 1 / phi(n)
}

impl PrivateKey {
    pub fn new(bit_size: usize, rng: &mut (impl Rng + CryptoRng)) -> Self {
        loop {
            let p: BigUint = rng.gen_prime(bit_size, None);
            let q: BigUint = rng.gen_prime(bit_size, None);
            if p == q {
                continue;
            }
            let n = &p * &q;
            let lambda: BigUint = &n + &BigUint::one() - &p - &q;
            let mu = if let Some(mu) = lambda.clone().invm(&n) {
                mu
            } else {
                continue;
            };
            let n_2 = &n * &n;
            debug!("生成密钥：p = {}, q = {}", p, q);
            break Self { n, n_2, lambda, mu };
        }
    }

    pub fn decrypt(&self, c: &BigUint) -> Option<BigUint> {
        if BigUint::gcd(c, &self.n_2).is_one() {
            let l = |x| {
                let (q, r) = BigUint::div_rem(&(x - BigUint::one()), &self.n);
                if r.is_zero() {
                    trace!("{} 解密为 {}", c, q);
                    Some(q)
                } else {
                    None
                }
            };
            l(c.modpow(&self.lambda, &self.n_2)).map(|m_mu| m_mu * &self.mu % &self.n)
        } else {
            None
        }
    }
}

pub struct PublicKey {
    n: BigUint,
    n_2: BigUint,
    // g = n + 1
}
impl PublicKey {
    pub fn new(private_key: &PrivateKey) -> Self {
        Self {
            n: private_key.n.clone(),
            n_2: private_key.n_2.clone(),
        }
    }

    pub fn encrypt(&self, m: &BigUint, mut rng: impl Rng + CryptoRng) -> Option<BigUint> {
        if m < &self.n {
            let r = rng.gen_biguint_range(&BigUint::one(), &self.n);
            let r_n = r.modpow(&self.n, &self.n_2);
            // g^m = (1 + n)^m = (1 + nm) mod n^2
            let g_m = (&self.n * m + BigUint::one()) % &self.n_2;
            let c = g_m * r_n % &self.n_2;
            trace!("{} 加密为 {}", m, c);
            Some(c)
        } else {
            None
        }
    }

    pub fn add_encrypted(&self, lhs: &BigUint, rhs: &BigUint) -> Option<BigUint> {
        if BigUint::gcd(lhs, &self.n_2).is_one() && BigUint::gcd(rhs, &self.n_2).is_one() {
            let res = lhs * rhs % &self.n_2;
            debug!("密文相乘：{} * {} = {}", lhs, rhs, res);
            Some(res)
        } else {
            None
        }
    }
    pub fn mul_encrypted(&self, lhs: &BigUint, rhs: &BigUint) -> Option<BigUint> {
        if BigUint::gcd(lhs, &self.n_2).is_one() && BigUint::gcd(rhs, &self.n_2).is_one() {
            let res = BigUint::modpow(lhs, rhs, &self.n_2);
            debug!("密文指数：{} ^ {} = {}", lhs, rhs, res);
            Some(res)
        } else {
            None
        }
    }
}
