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

//! A range of physical memory.

/// `size` bytes of physical memory at `start`, whose end does not overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::hii) struct PhysicalRange {
    start: u64,
    size: u64,
}

impl PhysicalRange {
    /// `size` bytes at `start`, unless the end overflows.
    pub(in crate::hii) fn new(start: u64, size: u64) -> Option<Self> {
        start.checked_add(size)?;
        Some(Self { start, size })
    }

    /// The range from `start` to `end`, both inclusive, unless `end` is before `start` or the
    /// range ends past the end of memory.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
    pub(in crate::hii) fn from_inclusive(start: u64, end: u64) -> Option<Self> {
        Self::new(start, end.checked_sub(start)?.checked_add(1)?)
    }

    #[cfg(test)]
    pub(in crate::hii) fn start(self) -> u64 {
        self.start
    }

    /// The end, exclusive.
    pub(in crate::hii) fn end(self) -> u64 {
        // Cannot overflow: new checked it.
        self.start + self.size
    }

    /// Whether the range holds `length` bytes at `address`.
    pub(in crate::hii) fn holds(self, address: u64, length: u64) -> bool {
        address
            .checked_sub(self.start)
            .and_then(|offset| self.size.checked_sub(offset))
            .is_some_and(|room| length <= room)
    }

    /// Whether the range shares a byte with `length` bytes at `address`.
    pub(in crate::hii) fn overlaps(self, address: u64, length: u64) -> bool {
        match address.checked_sub(self.start) {
            // `address` is in or past the range.
            Some(offset) => length > 0 && offset < self.size,
            // `address` is before the range: the bytes reach it.
            None => self.size > 0 && self.start.abs_diff(address) < length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_inclusive_takes_both_ends() {
        for (case, start, end, want) in [
            ("one byte", 0x1000, 0x1000, Some((0x1000, 0x1001))),
            ("a page", 0x1000, 0x1fff, Some((0x1000, 0x2000))),
            ("an end before the start", 0x1000, 0xfff, None),
            ("the last byte of memory", u64::MAX, u64::MAX, None),
            ("all of memory", 0, u64::MAX, None),
        ] {
            let got =
                PhysicalRange::from_inclusive(start, end).map(|range| (range.start(), range.end()));
            assert_eq!(got, want, "{case}");
        }
    }

    #[test]
    fn new_refuses_an_end_past_the_end_of_memory() {
        assert_eq!(
            PhysicalRange::new(u64::MAX - 0x1000, 0x1000).map(PhysicalRange::end),
            Some(u64::MAX),
            "an end at the end of memory"
        );
        assert_eq!(
            PhysicalRange::new(u64::MAX - 0xfff, 0x1000),
            None,
            "an end past it"
        );
    }
}
