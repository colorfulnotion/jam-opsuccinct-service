# JAM Service: OP Succinct Proof of Finality Verification 

Using on [Polkadot JAM SDK](https://hackmd.io/@polkadot/jamsdk), this
takes a Groth16 proof and verifies it. The service is designed to take
Groth16 proofs of finality for OP Succinct chains and verify them in
refine and solicit (and forget) blocks in accumulate, doing whatever
bookkeeping required.

## Basic 

The actual input for OP Succinct will be a [Groth16
proof](https://github.com/succinctlabs/sp1/tree/dev/examples/groth16)
from a OP Succinct chain like Phala posted to ETH Kainnet.  Groth16
proofs can be verified within JAM Services already because they
support `no_std` and are lower latency than Plonk proofs.

As of early December, Phala is posting to Sepolia in a transaction
like
[this](https://sepolia.etherscan.io/tx/0xb979469cfdc348ae39044fe11e501928d93ae90c416b2ec7df7a70f39acac497)
to its [OP Succinct
Contract](https://sepolia.etherscan.io/address/0x30094da24be28682f2d647d405011d1d0be154cb):

* `_outputRoot` bytes32 - 0x94df86f9d1f61f93f8e32a46b747e8202024241dc2e8e8f7f402326a2686ed1a
* `_l2BlockNumber` uint256 4982488
* `_l1BlockNumber` uint256 7132618
* `_proof` bytes `0x09069090083932701d28af369122f1b3d0d5ce3a3606a9845fc73c1d6c6075121bd200ed1fb1a042e44d8263b8518feead8247185debe8a9f545a08b57efcd6fdc30c1e11581b23dbd3648c4ebdc64ef486134aaa844de557c121684c4fcd69ebb80473403991a967f5944d4234c673dc3dd8c4a895a1cb5a5600517c4bd13a217fe911a2fed0f6a02d12955be3cc724fe92cc2bc19b3ab0a8a1ff3b371dd1924c771400180d111a2b1aa003a3e2601285931919ca35f7e301a421b1146db406422ce2d70098276827cf642feabff3f963d3fc82a22ae9643a68db416f27efb9a9c2c6ff155d3d330ae462341455b8367b0c18334e4a1c9973c9899303b02e7bdc737cc2`

A proof posted like the above is 260 bytes and also requires a
verifier key (32 bytes) and a public byte (12 bytes).

Given N OP Succinct chains, the process of proving that all N of them have achieved finality involve aggreating 2N+1 Groth16 proofs into just ONE Groth16 proof:
* (A) N proofs of like 1 hour of OP Succinct chains proof of validity generating N state roots; 
* (B) N proofs of each of N OP Succinct chain's L1 Contract having N different state roots, using a storage proof like [this](https://github.com/zkzoomer/sp1-storage-proof/blob/main/script/src/bin/main.rs#L17-L27)
* (C) 1 proof that the the L1 block has been finalized according to the Beacon chain

These 2N+1 proofs can be compressed into just 1 Groth16 proof following [this](https://github.com/succinctlabs/sp1/blob/dev/examples/groth16/program/src/main.rs).  You can verify however many you want by slightly tweaking the example linked above, then you take that program (verifying N groth proofs) and create a single groth proof from that.   Then we supply the Groth proof into this service.

## Open Questions

* How are (A) + (B) for 1 of the N op succinct chains directly connected -- where the state root after 1 hour (say) of OP succinct activity (of the L2 on it’s own) in (A) is _the same as_ the state root of the inclusion proof in the L2s contract on L1 in (B)?



# WIP

At present the data within `refine` comes from the proof generated from this:

```
//! A script that generates a Groth16 proof for the Fibonacci program, saves the outputs to disk, and verifies the proof in SP1.

use sp1_sdk::{include_elf, utils, HashableKey, ProverClient, SP1Stdin};
use sp1_verifier::Groth16Verifier;
use std::fs::File;
use std::io::{Read, Write};

/// The ELF for the Groth16 verifier program.
const GROTH16_ELF: &[u8] = include_elf!("groth16-verifier-program");

/// The ELF for the Fibonacci program.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// Generates the proof, public values, and vkey hash for the Fibonacci program in a format that
/// can be read by `sp1-verifier`.
///
/// Returns the proof bytes, public values, and vkey hash.
fn generate_fibonacci_proof() -> (Vec<u8>, Vec<u8>, String) {
    // Create an input stream and write '20' to it.
    let n = 20u32;

    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    // Create a `ProverClient`.
    let client = ProverClient::new();

    // Generate the groth16 proof for the Fibonacci program.
    let (pk, vk) = client.setup(FIBONACCI_ELF);
    println!("vk: {:?}", vk.bytes32());
    let proof = client.prove(&pk, stdin).groth16().run().unwrap();
    (proof.bytes(), proof.public_values.to_vec(), vk.bytes32())
}

fn save_to_file(filename: &str, data: &[u8]) {
    let mut file = File::create(filename).expect("Failed to create file");
    file.write_all(data).expect("Failed to write data to file");
}

fn read_from_file(filename: &str) -> Vec<u8> {
    let mut file = File::open(filename).expect("Failed to open file");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Failed to read data from file");
    data
}


fn main() {
    // Setup logging.
    utils::setup_logger();

    // Generate the Fibonacci proof, public values, and vkey hash.
    let (fibonacci_proof, fibonacci_public_values, vk) = generate_fibonacci_proof();

    // Save the proof, public values, and vkey hash to disk.
    save_to_file("proof.bin", &fibonacci_proof);
    save_to_file("public.bin", &fibonacci_public_values);
    save_to_file("vk.bin", vk.as_bytes());

    println!("Saved proof, public values, and vk to disk.");

    // Clone the values to prevent ownership issues.
    let proof_clone = fibonacci_proof.clone();
    let public_values_clone = fibonacci_public_values.clone();

    // Write the proof, public values, and vkey hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(fibonacci_proof);
    stdin.write_vec(fibonacci_public_values);
    stdin.write(&vk);

    // Read the proof, public values, and vkey hash back from disk.
    let proof = read_from_file("proof.bin");
    let public_values = read_from_file("public.bin");
    let vk_bytes = read_from_file("vk.bin");
    let vk = String::from_utf8(vk_bytes).expect("Failed to convert vk to string");

    let groth16_vk = sp1_verifier::GROTH16_VK_BYTES.as_ref();

    // Verify the Groth16 proof from disk
    let result = Groth16Verifier::verify(&proof, &public_values, &vk, groth16_vk);


    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {:?}", e);
        }
    }
    
    // Verify the Groth16 proof from the memory
    let result2 = Groth16Verifier::verify(&proof_clone, &public_values_clone, &vk, groth16_vk);
    match result2 {
        Ok(()) => {
            println!("Proof2 is valid");
        }
        Err(e) => {
            println!("Error verifying proof2: {:?}", e);
        }
    }
}
```

This can be verified:

```
#![no_std]

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use sp1_verifier::Groth16Verifier;
use alloc::vec;

fn main() {
    // Define the u8 vectors directly instead of reading from files.
    let proof: Vec<u8> = vec![9, 6, 144, 144, 44, 97, 246, 251, 229, 151, 210, 230, 246, 193, 219, 115, 153, 19, 222, 218, 20, 110, 182, 175, 33, 180, 216, 17, 134, 54, 38, 33, 54, 218, 160, 173, 32, 224, 56, 178, 175, 163, 181, 19, 165, 247, 209, 168, 252, 221, 98, 33, 20, 213, 235, 169, 113, 161, 32, 165, 225, 69, 242, 69, 149, 95, 93, 180, 8, 229, 95, 110, 193, 16, 196, 217, 84, 145, 239, 16, 132, 104, 129, 93, 23, 108, 224, 170, 161, 130, 124, 245, 66, 113, 252, 231, 153, 25, 100, 200, 4, 70, 120, 10, 83, 149, 115, 175, 64, 238, 196, 65, 70, 28, 34, 215, 135, 155, 229, 185, 172, 112, 1, 174, 89, 192, 136, 70, 160, 124, 145, 15, 46, 150, 114, 182, 57, 80, 183, 101, 138, 7, 49, 132, 120, 2, 33, 83, 225, 168, 245, 173, 124, 143, 162, 255, 237, 52, 164, 189, 60, 23, 9, 84, 45, 227, 210, 252, 153, 144, 143, 199, 218, 172, 236, 230, 180, 78, 164, 253, 35, 181, 58, 230, 100, 44, 28, 3, 227, 2, 233, 217, 49, 98, 214, 75, 30, 97, 213, 17, 3, 164, 197, 179, 39, 183, 43, 15, 227, 22, 161, 235, 71, 73, 52, 213, 176, 157, 180, 78, 212, 126, 60, 133, 150, 96, 246, 169, 6, 45, 0, 82, 77, 52, 187, 102, 85, 168, 129, 153, 158, 50, 2, 229, 252, 142, 237, 169, 69, 194, 169, 250, 25, 214, 227, 225, 64, 161, 120, 47];
    let public_values: Vec<u8> = vec![20, 0, 0, 0, 109, 26, 0, 0, 211, 11, 0, 0];
    let vk_bytes: Vec<u8> = vec![48, 120, 48, 48, 54, 56, 52, 56, 99, 100, 100, 51, 99, 54, 48, 51, 99, 51, 57, 54, 57, 51, 49, 99, 99, 102, 49, 51, 99, 98, 57, 56, 102, 99, 50, 100, 57, 49, 55, 98, 52, 100, 49, 100, 50, 100, 55, 55, 102, 52, 54, 98, 53, 56, 50, 97, 102, 57, 98, 50, 51, 48, 55, 53, 98, 56];
    let vk = String::from_utf8(vk_bytes).expect("Failed to convert vk to string");
    let groth16_vk = sp1_verifier::GROTH16_VK_BYTES.as_ref();
    let result = Groth16Verifier::verify(&proof, &public_values, &vk, groth16_vk);
    match result {
        Ok(()) => {
        }
        Err(_e) => {
        }
    }
}
```





