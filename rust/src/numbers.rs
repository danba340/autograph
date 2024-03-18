use crate::types::{Index, Size};

pub fn get_uint32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub fn set_uint32(bytes: &mut [u8], offset: usize, number: u32) {
    bytes[offset..offset + 4].copy_from_slice(number.to_be_bytes().as_slice());
}

pub fn get_uint64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

pub fn set_uint64(bytes: &mut [u8], offset: usize, number: u64) {
    bytes[offset..offset + 8].copy_from_slice(number.to_be_bytes().as_slice());
}

pub fn read_index(index: Index) -> u32 {
    get_uint32(&index, 0)
}

pub fn read_size(size: Size) -> usize {
    get_uint64(&size, 0) as usize
}

pub fn set_size(bytes: &mut Size, size: usize) {
    set_uint64(bytes, 0, size as u64)
}
