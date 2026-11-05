// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Arrays that firmware lays out at any alignment, read value by value.

/// The `count` values of type `T` from `start` on, each read at any alignment when the iterator
/// reaches it.
///
/// # Safety
///
/// `start` points at `count` initialized values of `T` in one allocation, which need not be
/// aligned and which stay unchanged until the iterator is dropped.
pub(crate) unsafe fn read_unaligned_array<T>(
    start: *const T,
    count: usize,
) -> impl Iterator<Item = T> {
    (0..count).map(move |index| {
        // SAFETY: index < count, and the caller's contract covers the `count` values from `start`
        unsafe { start.wrapping_add(index).read_unaligned() }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// read_unaligned_array reads each value at its own index, from an odd address, and none
    /// past `count`, though the bytes after the 3 values hold a fourth.
    #[test]
    fn read_unaligned_array_reads_each_value_at_any_alignment() {
        let values = [0x0403_0201_u32, 0x0807_0605, 0x0c0b_0a09];
        let bytes = [
            &[0xee][..],
            &values.map(u32::to_ne_bytes).concat()[..],
            &[0xee; 4],
        ]
        .concat();
        let start = bytes.as_ptr().wrapping_add(1).cast::<u32>();

        // SAFETY: `bytes` holds the 3 values from `start` on, and outlives the iterator
        let read: Vec<u32> = unsafe { read_unaligned_array(start, values.len()) }.collect();

        assert_eq!(read, values, "the 3 values from an odd address");
    }
}
