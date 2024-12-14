//! JAM OP Succinct Proof of Finality Service
//!
//! Use by concatenating one or more encoded `Instruction`s into a work item's payload.

#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_std)]
#![cfg_attr(any(target_arch = "riscv32", target_arch = "riscv64"), no_main)]
#![allow(clippy::unwrap_used)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use alloc::string::String;
use jam_pvm_common::{
    //accumulate::*,
    //refine::{export_slice, import},
    *,
};
use jam_types::*;
use sp1_verifier::Groth16Verifier;

#[cfg(not(any(target_arch = "riscv32", target_arch = "riscv64")))]
fn main() {}

#[allow(dead_code)]
struct Service;
jam_pvm_common::declare_service!(Service);

impl jam_pvm_common::Service for Service {
    fn refine(
        id: ServiceId,
        _payload: WorkPayload,
        _package_info: PackageInfo,
        _extrinsics: Vec<Vec<u8>>,
    ) -> WorkOutput {
        info!(target = "boot", "Executing refine for service #{id}");

        let mut out = vec![];
        let proof: Vec<u8> = vec![
            9, 6, 144, 144, 44, 97, 246, 251, 229, 151, 210, 230, 246, 193, 219, 115, 153, 19, 222,
            218, 20, 110, 182, 175, 33, 180, 216, 17, 134, 54, 38, 33, 54, 218, 160, 173, 32, 224,
            56, 178, 175, 163, 181, 19, 165, 247, 209, 168, 252, 221, 98, 33, 20, 213, 235, 169,
            113, 161, 32, 165, 225, 69, 242, 69, 149, 95, 93, 180, 8, 229, 95, 110, 193, 16, 196,
            217, 84, 145, 239, 16, 132, 104, 129, 93, 23, 108, 224, 170, 161, 130, 124, 245, 66,
            113, 252, 231, 153, 25, 100, 200, 4, 70, 120, 10, 83, 149, 115, 175, 64, 238, 196, 65,
            70, 28, 34, 215, 135, 155, 229, 185, 172, 112, 1, 174, 89, 192, 136, 70, 160, 124, 145,
            15, 46, 150, 114, 182, 57, 80, 183, 101, 138, 7, 49, 132, 120, 2, 33, 83, 225, 168,
            245, 173, 124, 143, 162, 255, 237, 52, 164, 189, 60, 23, 9, 84, 45, 227, 210, 252, 153,
            144, 143, 199, 218, 172, 236, 230, 180, 78, 164, 253, 35, 181, 58, 230, 100, 44, 28, 3,
            227, 2, 233, 217, 49, 98, 214, 75, 30, 97, 213, 17, 3, 164, 197, 179, 39, 183, 43, 15,
            227, 22, 161, 235, 71, 73, 52, 213, 176, 157, 180, 78, 212, 126, 60, 133, 150, 96, 246,
            169, 6, 45, 0, 82, 77, 52, 187, 102, 85, 168, 129, 153, 158, 50, 2, 229, 252, 142, 237,
            169, 69, 194, 169, 250, 25, 214, 227, 225, 64, 161, 120, 47,
        ];
        let public_values: Vec<u8> = vec![20, 0, 0, 0, 109, 26, 0, 0, 211, 11, 0, 0];
        let vk_bytes: Vec<u8> = vec![
            48, 120, 48, 48, 54, 56, 52, 56, 99, 100, 100, 51, 99, 54, 48, 51, 99, 51, 57, 54, 57,
            51, 49, 99, 99, 102, 49, 51, 99, 98, 57, 56, 102, 99, 50, 100, 57, 49, 55, 98, 52, 100,
            49, 100, 50, 100, 55, 55, 102, 52, 54, 98, 53, 56, 50, 97, 102, 57, 98, 50, 51, 48, 55,
            53, 98, 56,
        ];
        let vk = String::from_utf8(vk_bytes).expect("Failed to convert vk to string");
        let groth16_vk = sp1_verifier::GROTH16_VK_BYTES.as_ref();
        let result = Groth16Verifier::verify(&proof, &public_values, &vk, groth16_vk);
        match result {
            Ok(()) => {
                out.push(123);
            }
            Err(_e) => {
                out.push(456);
            }
        }
        info!(target = "opsuccinct", "Returning {:?} into accumulate", out);
        out.encode().into()
    }

    fn accumulate(_slot: Slot, _id: ServiceId, _results: Vec<AccumulateItem>) {}

    fn on_transfer(_slot: Slot, _id: ServiceId, _items: Vec<TransferRecord>) {}
}
