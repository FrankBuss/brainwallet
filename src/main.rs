use base58::*;
use libsecp256k1::*;
use ripemd160::Ripemd160;
use sha2::{Digest, Sha256};
use std::{env, process};

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().as_slice().try_into().unwrap()
}

fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().as_slice().try_into().unwrap()
}

fn create_key_pair(seed: &[u8]) -> (SecretKey, PublicKey) {
    let seed_bytes = sha256_hash(seed);
    let secret_key = SecretKey::parse(&seed_bytes).unwrap();
    let public_key = PublicKey::from_secret_key(&secret_key);
    (secret_key, public_key)
}

fn calculate_bitcoin_address(public_key: PublicKey, compressed: bool) -> String {
    let public_key_serialized = if compressed {
        public_key.serialize_compressed().to_vec()
    } else {
        public_key.serialize().to_vec()
    };
    let hashed = ripemd160(&sha256_hash(&public_key_serialized));
    const BITCOIN_PUBLIC_KEY_MAIN_NETWORK: u8 = 0x00; // 0x6f for testnet
    let mut bytes = [&[BITCOIN_PUBLIC_KEY_MAIN_NETWORK], hashed.as_ref()].concat();
    let double_hash = sha256_hash(&sha256_hash(&bytes).to_vec());
    let checksum = &double_hash[0..4];
    bytes.extend(checksum);
    bytes.to_base58()
}

fn calculate_wallet_import_format(secret_key: SecretKey, compressed: bool) -> String {
    let secret_key_serialized = secret_key.serialize();
    const BITCOIN_PRIVATE_KEY_MAIN_NETWORK: u8 = 0x80; // 0xef for testnet
    let mut bytes = [
        &[BITCOIN_PRIVATE_KEY_MAIN_NETWORK],
        secret_key_serialized.as_ref(),
    ]
    .concat();
    if compressed {
        bytes.push(1);
    }
    let double_hash = sha256_hash(&sha256_hash(&bytes).to_vec());
    let checksum = &double_hash[0..4];
    bytes.extend(checksum);
    bytes.to_base58()
}

fn show_usage(program_name: &str) -> ! {
    eprintln!(
        "usage: {} [compressed|uncompressed] passphrase",
        program_name
    );
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        show_usage(&args[0]);
    }
    let compressed;
    match args[1].as_ref() {
        "compressed" => compressed = true,
        "uncompressed" => compressed = false,
        _ => show_usage(&args[0]),
    }
    let passphrase = &args[2];
    let (secret_key, public_key) = create_key_pair(passphrase.as_bytes());
    let bitcoin_address = calculate_bitcoin_address(public_key, compressed);
    println!("Bitcoin Address: {}", bitcoin_address);
    let wif = calculate_wallet_import_format(secret_key, compressed);
    println!("Private Key (Wallet Import Format): {}", wif);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(
        passphrase: &str,
        compressed: bool,
        expected_bitcoin_address: &str,
        expected_wif: &str,
    ) {
        let (secret_key, public_key) = create_key_pair(passphrase.as_bytes());
        let bitcoin_address = calculate_bitcoin_address(public_key, compressed);
        assert_eq!(bitcoin_address, expected_bitcoin_address);
        let wif = calculate_wallet_import_format(secret_key, compressed);
        assert_eq!(wif, expected_wif);
    }

    #[test]
    fn test_uncompressed() {
        test(
            "123456789012345",
            false,
            "1LACc1FBbR5o3qxhkY1nRZGkMeWJ9VZJim",
            "5KY2ffqAZPrnvoMAJr2sTDKpBDdF3bpqr2NgKizDMJ8n23Uq5mc",
        );
    }

    #[test]
    fn test_compressed() {
        test(
            "123456789012345",
            true,
            "1FCGr3TqJ59vjRsZtSLvaTSANeGz81gc7Y",
            "L4oxMgPbBytmiTZz5mRFghQ3E6ixzUiAbP4gZeKXWadKhXyLGoVw",
        );
    }
}
