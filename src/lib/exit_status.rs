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

//! The status that the UEFI Shell build's image returns for the exit code of main.

/// EFI_ABORTED: the error bit, the top bit of UINTN, and 21.
const EFI_ABORTED: usize = !(usize::MAX >> 1) | 21;

/// The status of the image for `code`, the exit code of main that std's efi_main returns:
/// EFI_ABORTED for ExitCode::FAILURE, 1, which as a status would be the warning
/// EFI_WARN_UNKNOWN_GLYPH, and `code` itself else.
#[cfg_attr(
    not(target_os = "uefi"),
    allow(
        dead_code,
        reason = "the UEFI build's entry point and the tests call it"
    )
)]
pub(crate) fn efi_status(code: usize) -> usize {
    match code {
        1 => EFI_ABORTED,
        code => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_is_aborted() {
        let error_bit = 1 << (usize::BITS - 1);
        let cases = [(0, 0), (1, error_bit | 21), (2, 2)];
        for (code, status) in cases {
            assert_eq!(efi_status(code), status, "exit code {code}");
        }
    }
}
