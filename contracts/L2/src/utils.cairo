use core::keccak::keccak_u256s_be_inputs;

pub fn hash(a: u256, b: u256, c: u256) -> felt252 {
    let inputs = array![a, b, c];
    let hash = keccak_u256s_be_inputs(inputs.span());
    hash.try_into().unwrap()
}
