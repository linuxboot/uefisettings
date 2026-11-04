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

//! Secrets, such as passwords, read from the files that flags name, `-` naming standard input.
//! Line mode reads passwords, certificates and signatures; file mode reads keys and raw password
//! bytes. Both read a [`Read`] that the binary opened into a [`Secret`], whose buffer is sized up
//! front and zeroized on drop. In the UEFI Shell, `-` is a redirected file, a pipe or the console,
//! read through [`ShellStdin`] and [`ShellConsole`].

use std::fmt;
use std::io;
use std::io::Read;
use std::ops::RangeInclusive;
use std::str;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use subtle::Choice;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// The largest cap that the readers take: 64 KiB, for a PEM key or certificate.
pub const MAX_SECRET_LEN: usize = 64 * 1024;

/// The most CHAR16s that encode_ucs2 fills: an EFI_IFR_PASSWORD's MaxSize, a UINT16 (UEFI 2.11
/// §33.3.8.3.54), plus the terminator of the string that NewString takes (§34.3.2).
pub const MAX_UCS2_UNITS: usize = 1 << 16;

/// The bytes past the cap that line mode reads: a CRLF at the cap, then one that shows the line
/// too long.
const LINE_SLACK: usize = 3;

/// The byte order mark that the Shell's UCS-2 files and pipes start with.
const BYTE_ORDER_MARK: u16 = 0xFEFF;

/// The buffer of the second ReadFile(), which must read nothing: 2 CHAR16s, the fewest with which
/// `<a` reads a byte even at position 0, where it stores U+FEFF first (edk2-stable202608
/// ShellPkg/Application/Shell/FileHandleWrappers.c:2004-2013).
const SECOND_READ_LEN: usize = 4;

/// The Private Use Area of the Basic Multilingual Plane, which UEFI prohibits (UEFI 2.11
/// §33.2.6.2.1) and where its strings encode font display codes, 0xF6yy to 0xF8zz (§33.2.6.2.4).
const PRIVATE_USE_AREA: RangeInclusive<u16> = 0xE000..=0xF8FF;

/// The bytes of a secret, zeroized on drop. Debug and Display show only its length, and it
/// compares only in constant time.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Its bytes: UTF-8 from line mode and the Shell's `-`, raw from file mode.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-byte secret", self.0.len())
    }
}

impl ConstantTimeEq for Secret {
    /// In constant time for secrets of equal length; unequal lengths differ at once.
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

/// Why a secret was refused. No variant holds a byte of the secret.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SecretError {
    #[error("cannot read the secret")]
    Read(#[source] io::Error),
    #[error("a cap of {max_len} bytes is over the limit of {limit} bytes", limit = MAX_SECRET_LEN)]
    CapTooLarge { max_len: usize },
    #[error("the secret is empty")]
    Empty,
    #[error("the secret is longer than {max_len} bytes")]
    TooLong { max_len: usize },
    #[error("the secret holds a NUL byte")]
    Nul,
    #[error("the secret holds a line break other than one at its end")]
    LineBreak,
    #[error("the secret is not UTF-8")]
    NotUtf8,
    #[error("Esc aborted the secret")]
    Aborted,
    #[error("a key other than a character, Enter, Backspace or Esc")]
    UnsupportedKey,
    #[error("the keystrokes ended before Enter")]
    KeystrokesEnded,
    #[error("standard input already gave a secret: at most one flag may name -")]
    StdinClaimed,
    #[error(
        "standard input is a terminal, which would echo the secret: pipe or redirect it into -"
    )]
    StdinTerminal,
    #[error("standard input is neither a file, a pipe nor the console: redirect a file into - with < or <a, or pipe it with |")]
    StdinUnreadable,
    #[error("ReadFile() of standard input reported a size that neither < and | (its FileSize) nor <a (twice its FileSize) give")]
    UnexpectedReadSize,
    #[error("standard input holds more than its FileSize")]
    LongerThanFileSize,
    #[error("standard input has an odd length, which UCS-2 cannot")]
    OddLength,
    #[error(
        "standard input does not start with U+FEFF, as UCS-2 does: redirect an ASCII file with <a"
    )]
    NoByteOrderMark,
    #[error(
        "<a takes each byte for a character, and one is above U+007F: redirect a UCS-2 file with <"
    )]
    NotAscii,
    #[error("standard input holds an unpaired UTF-16 surrogate")]
    UnpairedSurrogate,
    #[error("a UCS-2 buffer of {units} CHAR16s is over the limit of {limit}", limit = MAX_UCS2_UNITS)]
    Ucs2BufferTooLarge { units: usize },
    #[error("the secret holds a character outside the Basic Multilingual Plane, which UCS-2 cannot encode")]
    OutsideBmp,
    #[error("the secret holds a character of the Private Use Area, which UEFI prohibits")]
    PrivateUse,
    #[error("the secret holds more than {max_units} characters")]
    TooManyCharacters { max_units: usize },
}

/// Line mode: one line of at most `max_len` UTF-8 bytes, once one trailing LF, CR or CRLF is
/// removed. Refuses an empty line, NUL, any other LF or CR, and invalid UTF-8. Reads at most
/// `max_len`+3 bytes.
pub fn read_secret_line(reader: impl Read, max_len: usize) -> Result<Secret, SecretError> {
    let line = read_at_most(reader, buffer_len(max_len, LINE_SLACK)?)?;
    line_secret(line, max_len)
}

/// File mode: the whole input, raw, at most `max_len` bytes. Refuses an empty input. Reads at
/// most `max_len`+1 bytes.
pub fn read_secret_file(reader: impl Read, max_len: usize) -> Result<Secret, SecretError> {
    let bytes = read_at_most(reader, buffer_len(max_len, 1)?)?;
    match bytes.len() {
        0 => Err(SecretError::Empty),
        len if len > max_len => Err(SecretError::TooLong { max_len }),
        _ => Ok(Secret(bytes)),
    }
}

/// `max_len` plus `slack`, the size of a reader's buffer, for a cap of at most MAX_SECRET_LEN.
fn buffer_len(max_len: usize, slack: usize) -> Result<usize, SecretError> {
    match max_len {
        0..=MAX_SECRET_LEN => max_len.checked_add(slack),
        _ => None,
    }
    .ok_or(SecretError::CapTooLarge { max_len })
}

/// At most `limit` bytes of `reader`, in a buffer allocated to `limit` and never grown.
fn read_at_most(mut reader: impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let mut buffer = Zeroizing::new(vec![0; limit]);
    let mut filled = 0;
    while let Some(unfilled) = buffer
        .get_mut(filled..)
        .filter(|unfilled| !unfilled.is_empty())
    {
        let unfilled_len = unfilled.len();
        match reader.read(unfilled) {
            Ok(0) => break,
            Ok(count) if count <= unfilled_len => filled += count,
            Ok(_) => {
                return Err(SecretError::Read(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the reader reported more bytes than its buffer holds",
                )))
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(SecretError::Read(error)),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Line mode's rules on `line`, once one trailing LF, CR or CRLF is removed.
fn line_secret(mut line: Zeroizing<Vec<u8>>, max_len: usize) -> Result<Secret, SecretError> {
    let terminator_len = match line.as_slice() {
        [.., b'\r', b'\n'] => 2,
        [.., b'\n' | b'\r'] => 1,
        _ => 0,
    };
    let content_len = line.len().saturating_sub(terminator_len);
    line.truncate(content_len);
    check_line(&line, max_len)?;
    Ok(Secret(line))
}

/// Refuses a line that is empty, over `max_len` bytes, holds NUL, LF or CR, or is not UTF-8.
fn check_line(line: &[u8], max_len: usize) -> Result<(), SecretError> {
    if line.is_empty() {
        return Err(SecretError::Empty);
    }
    if line.len() > max_len {
        return Err(SecretError::TooLong { max_len });
    }
    if line.contains(&0) {
        return Err(SecretError::Nul);
    }
    if line.iter().any(|byte| matches!(byte, b'\n' | b'\r')) {
        return Err(SecretError::LineBreak);
    }
    str::from_utf8(line).map_err(|_| SecretError::NotUtf8)?;
    Ok(())
}

/// A key read at the UEFI Shell's console, for read_typed_secret. Debug hides the character.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Keystroke {
    /// Enter, CHAR_CARRIAGE_RETURN, which ends the secret
    Enter,
    /// Backspace, CHAR_BACKSPACE, which deletes the last character
    Backspace,
    /// Esc, SCAN_ESC, which aborts the secret
    Escape,
    /// A character of the secret
    Char(char),
    /// Any other key without a character, such as an arrow, which refuses the secret
    Other,
}

impl fmt::Debug for Keystroke {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enter => f.write_str("Enter"),
            Self::Backspace => f.write_str("Backspace"),
            Self::Escape => f.write_str("Escape"),
            Self::Char(_) => f.write_str("Char(..)"),
            Self::Other => f.write_str("Other"),
        }
    }
}

/// The secret typed as `keystrokes`, unechoed: Enter ends it, Backspace deletes the last
/// character, Esc aborts, and a character that takes it past `max_len` UTF-8 bytes refuses it.
/// Line mode's rules then apply, with no terminator to remove.
pub fn read_typed_secret(
    keystrokes: impl IntoIterator<Item = io::Result<Keystroke>>,
    max_len: usize,
) -> Result<Secret, SecretError> {
    let mut typed = Zeroizing::new(Vec::with_capacity(buffer_len(max_len, 0)?));
    for keystroke in keystrokes {
        match keystroke.map_err(SecretError::Read)? {
            Keystroke::Enter => {
                check_line(&typed, max_len)?;
                return Ok(Secret(typed));
            }
            Keystroke::Backspace => delete_last_character(&mut typed),
            Keystroke::Escape => return Err(SecretError::Aborted),
            Keystroke::Char(character) => push_utf8(&mut typed, character, max_len)
                .map_err(|BufferFull| SecretError::TooLong { max_len })?,
            Keystroke::Other => return Err(SecretError::UnsupportedKey),
        }
    }
    Err(SecretError::KeystrokesEnded)
}

/// A character did not fit: push_utf8's error.
struct BufferFull;

/// Appends the UTF-8 of `character` to `buffer`, unless that takes it past `limit` bytes.
fn push_utf8(buffer: &mut Vec<u8>, character: char, limit: usize) -> Result<(), BufferFull> {
    let mut encoding = Zeroizing::new([0; 4]);
    let utf8 = character.encode_utf8(&mut encoding[..]).as_bytes();
    match buffer.len().checked_add(utf8.len()) {
        Some(len) if len <= limit => {
            buffer.extend_from_slice(utf8);
            Ok(())
        }
        _ => Err(BufferFull),
    }
}

/// Removes the UTF-8 bytes of the last character of `typed`, zeroizing them.
fn delete_last_character(typed: &mut Vec<u8>) {
    // A character starts at the last byte that is not a continuation byte, 0x80..=0xBF.
    let start = typed
        .iter()
        .rposition(|byte| !matches!(byte, 0x80..=0xBF))
        .unwrap_or(0);
    if let Some(deleted) = typed.get_mut(start..) {
        deleted.zeroize();
    }
    typed.truncate(start);
}

/// The UEFI Shell's standard input, EFI_SHELL_PARAMETERS_PROTOCOL.StdIn, through
/// EFI_SHELL_PROTOCOL, for read_shell_secret.
pub trait ShellStdin {
    /// The FileSize that GetFileInfo() gives: for a `<` or `<a` file and a `|` pipe; None where it
    /// fails, as on the console and for `<v`.
    fn file_size(&self) -> io::Result<Option<u64>>;

    /// One ReadFile() into `buffer`: the size it reports, which for `<a` leaves out the U+FEFF it
    /// stores first.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize>;
}

/// The UEFI Shell's console, for read_shell_secret.
pub trait ShellConsole {
    /// The keys typed at the console, read as they arrive
    type Keystrokes: Iterator<Item = io::Result<Keystroke>>;

    /// Whether gST->ConsoleInHandle carries EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL, as the console
    /// splitter's handle does, and the file-backed ConIn of the Shell's `<`, `<a` and `<v` does
    /// not.
    fn has_text_input_ex(&self) -> io::Result<bool>;

    /// The keystrokes of gST->ConIn, unechoed.
    fn keystrokes(&mut self) -> io::Result<Self::Keystrokes>;
}

/// The secret that `-` names in the UEFI Shell, in line mode at most `max_len` bytes: standard
/// input where GetFileInfo() sizes it, else keystrokes at the console where gST->ConsoleInHandle
/// carries SimpleTextInputEx. Any other standard input, such as `<v`, is refused, as a
/// redirected stdin must never be read as keystrokes.
pub fn read_shell_secret(
    stdin: &mut impl ShellStdin,
    console: &mut impl ShellConsole,
    max_len: usize,
) -> Result<Secret, SecretError> {
    let limit = buffer_len(max_len, LINE_SLACK)?;
    if let Some(file_size) = stdin.file_size().map_err(SecretError::Read)? {
        return read_redirected_secret(stdin, file_size, max_len, limit);
    }
    match console.has_text_input_ex().map_err(SecretError::Read)? {
        true => read_typed_secret(console.keystrokes().map_err(SecretError::Read)?, max_len),
        false => Err(SecretError::StdinUnreadable),
    }
}

/// How the Shell redirected standard input, by the size that ReadFile() reported.
#[derive(Clone, Copy)]
enum Redirection {
    /// `<a`: U+FEFF, then each byte of the file widened to a CHAR16
    Ascii,
    /// `<` or `|`: the UCS-2 of the file or the pipe as it is
    Unicode,
}

/// Line mode over the Shell's redirected standard input of FileSize `file_size`, of at most
/// `max_len` UTF-8 bytes in a buffer of `limit`. One ReadFile() of 2×`file_size`+2 bytes reads
/// it all, as `<a` stores U+FEFF and a CHAR16 per byte of the file
/// (edk2-stable202608 ShellPkg/Application/Shell/FileHandleWrappers.c:1994-2030), and a second
/// must read nothing. A stdin not read from position 0 fails the size or U+FEFF check.
fn read_redirected_secret(
    stdin: &mut impl ShellStdin,
    file_size: u64,
    max_len: usize,
    limit: usize,
) -> Result<Secret, SecretError> {
    // U+FEFF and `limit` CHAR16s; MAX_SECRET_LEN keeps these sizes far from overflowing.
    let bound = 2 * limit + 2;
    let file_size = match usize::try_from(file_size) {
        Ok(0) => return Err(SecretError::Empty),
        Ok(file_size) if file_size <= bound => file_size,
        _ => return Err(SecretError::TooLong { max_len }),
    };
    // What `<a` stores: U+FEFF and a CHAR16 per byte of the file.
    let stream_capacity = 2 * file_size + 2;
    let mut stream = Zeroizing::new(vec![0; stream_capacity]);
    let reported = stdin.read(&mut stream).map_err(SecretError::Read)?;
    let mut rest = Zeroizing::new([0; SECOND_READ_LEN]);
    if stdin.read(&mut rest[..]).map_err(SecretError::Read)? != 0 {
        return Err(SecretError::LongerThanFileSize);
    }
    let (redirection, stream_len) = match reported {
        reported if reported == file_size => (Redirection::Unicode, file_size),
        reported if reported == 2 * file_size || reported == stream_capacity => {
            (Redirection::Ascii, stream_capacity)
        }
        _ => return Err(SecretError::UnexpectedReadSize),
    };
    let stream = stream
        .get(..stream_len)
        .ok_or(SecretError::UnexpectedReadSize)?;
    let (units, odd) = stream.as_chunks::<2>();
    let mut units = units.iter().map(|&unit| u16::from_le_bytes(unit));
    // U+FEFF before the length, so that any ASCII file redirected with < is told of <a.
    if units.next() != Some(BYTE_ORDER_MARK) {
        return Err(SecretError::NoByteOrderMark);
    }
    if !odd.is_empty() {
        return Err(SecretError::OddLength);
    }
    match redirection {
        // <a widens each byte as Latin-1 (edk2-stable202608
        // MdePkg/Library/BaseLib/SafeString.c:2919-2920), so UTF-8 would arrive mangled.
        Redirection::Ascii
            if units
                .clone()
                .any(|unit| !u8::try_from(unit).is_ok_and(|byte| byte.is_ascii())) =>
        {
            return Err(SecretError::NotAscii)
        }
        Redirection::Ascii | Redirection::Unicode => {}
    }
    let mut line = Zeroizing::new(Vec::with_capacity(limit));
    for character in char::decode_utf16(units) {
        let character = character.map_err(|_| SecretError::UnpairedSurrogate)?;
        push_utf8(&mut line, character, limit)
            .map_err(|BufferFull| SecretError::TooLong { max_len })?;
    }
    line_secret(line, max_len)
}

/// `secret`, UTF-8, as `units` CHAR16s of little-endian UCS-2 padded with NUL, as
/// EFI_IFR_PASSWORD stores a password. Refuses NUL, which would end the password early, a
/// character outside the Basic Multilingual Plane or in its Private Use Area, and more characters
/// than `units`.
pub fn encode_ucs2(secret: &Secret, units: usize) -> Result<Secret, SecretError> {
    if units > MAX_UCS2_UNITS {
        return Err(SecretError::Ucs2BufferTooLarge { units });
    }
    let text = str::from_utf8(secret.as_bytes()).map_err(|_| SecretError::NotUtf8)?;
    let mut encoded = Zeroizing::new(vec![0; 2 * units]);
    let mut slots = encoded.as_chunks_mut::<2>().0.iter_mut();
    for character in text.chars() {
        let unit = match u16::try_from(u32::from(character)) {
            Ok(0) => return Err(SecretError::Nul),
            Ok(unit) if PRIVATE_USE_AREA.contains(&unit) => return Err(SecretError::PrivateUse),
            Ok(unit) => unit,
            Err(_) => return Err(SecretError::OutsideBmp),
        };
        let slot = slots
            .next()
            .ok_or(SecretError::TooManyCharacters { max_units: units })?;
        *slot = unit.to_le_bytes();
    }
    Ok(Secret(encoded))
}

/// Standard input as the source of one secret per process, which every `-` shares: a second
/// would read what the first left, or prompt again.
#[derive(Debug, Default)]
pub struct StdinClaim(AtomicBool);

impl StdinClaim {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Claims standard input for a secret; StdinClaimed after the first claim.
    pub fn claim(&self) -> Result<(), SecretError> {
        // Relaxed: the flag guards no other memory.
        match self.0.swap(true, Ordering::Relaxed) {
            false => Ok(()),
            true => Err(SecretError::StdinClaimed),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io;
    use std::io::Read;

    use subtle::ConstantTimeEq;
    use zeroize::Zeroizing;

    use super::*;

    /// The cap of passwords
    const PASSWORD_CAP: usize = 1024;
    /// The cap of certificates and signatures: one sysfs page with its LF
    const CERTIFICATE_CAP: usize = 4095;
    /// A secret that no message may show, of characters that no message holds otherwise
    const FIXTURE: &str = "Σ₩θяđƒ¹šħ";

    /// The variant of `error`. The match is exhaustive, so a new variant fails to compile here
    /// until no_message_shows_the_secret covers it.
    fn kind(error: &SecretError) -> &'static str {
        match error {
            SecretError::Read(_) => "Read",
            SecretError::CapTooLarge { .. } => "CapTooLarge",
            SecretError::Empty => "Empty",
            SecretError::TooLong { .. } => "TooLong",
            SecretError::Nul => "Nul",
            SecretError::LineBreak => "LineBreak",
            SecretError::NotUtf8 => "NotUtf8",
            SecretError::Aborted => "Aborted",
            SecretError::UnsupportedKey => "UnsupportedKey",
            SecretError::KeystrokesEnded => "KeystrokesEnded",
            SecretError::StdinClaimed => "StdinClaimed",
            SecretError::StdinTerminal => "StdinTerminal",
            SecretError::StdinUnreadable => "StdinUnreadable",
            SecretError::UnexpectedReadSize => "UnexpectedReadSize",
            SecretError::LongerThanFileSize => "LongerThanFileSize",
            SecretError::OddLength => "OddLength",
            SecretError::NoByteOrderMark => "NoByteOrderMark",
            SecretError::NotAscii => "NotAscii",
            SecretError::UnpairedSurrogate => "UnpairedSurrogate",
            SecretError::Ucs2BufferTooLarge { .. } => "Ucs2BufferTooLarge",
            SecretError::OutsideBmp => "OutsideBmp",
            SecretError::PrivateUse => "PrivateUse",
            SecretError::TooManyCharacters { .. } => "TooManyCharacters",
        }
    }

    /// A reader that counts the bytes it gives
    struct CountingReader<R> {
        inner: R,
        count: usize,
    }

    impl<R: Read> CountingReader<R> {
        fn new(inner: R) -> Self {
            Self { inner, count: 0 }
        }
    }

    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.inner.read(buffer)?;
            self.count += count;
            Ok(count)
        }
    }

    /// A reader that fails
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("the reader failed"))
        }
    }

    /// A reader whose first read fails with Interrupted, as read(2) fails with EINTR when a
    /// signal arrives before any byte
    struct InterruptedOnce<R> {
        inner: R,
        interrupted: bool,
    }

    impl<R: Read> InterruptedOnce<R> {
        fn new(inner: R) -> Self {
            Self {
                inner,
                interrupted: false,
            }
        }
    }

    impl<R: Read> Read for InterruptedOnce<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match std::mem::replace(&mut self.interrupted, true) {
                false => Err(io::ErrorKind::Interrupted.into()),
                true => self.inner.read(buffer),
            }
        }
    }

    /// A reader that reports a byte more than its buffer holds
    struct OverreportingReader;

    impl Read for OverreportingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            Ok(buffer.len() + 1)
        }
    }

    /// How a fake Shell standard input's ReadFile stores its stream
    #[derive(Clone, Copy)]
    enum Redirect {
        /// `<a`, as FileInterfaceFileRead (edk2-stable202608 FileHandleWrappers.c:1994-2030) reads:
        /// U+FEFF first at position 0, then each byte widened to a CHAR16, reporting 2 bytes per
        /// byte read and not the U+FEFF
        Ascii,
        /// An ASCII wrapper that reports the U+FEFF too
        AsciiReportingTag,
        /// `<` and `|`: the file's or the pipe's bytes as they are
        Unicode,
    }

    /// A Shell standard input over `content`, which GetFileInfo sizes as `file_size`, or fails
    struct FakeStdin {
        redirect: Redirect,
        file_size: Result<Option<u64>, io::ErrorKind>,
        content: Vec<u8>,
        position: usize,
        reads: usize,
    }

    impl FakeStdin {
        fn new(redirect: Redirect, content: &[u8]) -> Self {
            Self {
                redirect,
                file_size: Ok(Some(
                    u64::try_from(content.len()).expect("content length as u64"),
                )),
                content: content.to_vec(),
                position: 0,
                reads: 0,
            }
        }

        fn with_file_size(self, file_size: Option<u64>) -> Self {
            Self {
                file_size: Ok(file_size),
                ..self
            }
        }

        fn with_failing_file_size(self) -> Self {
            Self {
                file_size: Err(io::ErrorKind::Other),
                ..self
            }
        }
    }

    impl ShellStdin for FakeStdin {
        fn file_size(&self) -> io::Result<Option<u64>> {
            self.file_size.map_err(io::Error::from)
        }

        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            let remaining = &self.content[self.position..];
            let (tag_units, units) = match (self.redirect, self.position) {
                (Redirect::Unicode, _) => {
                    let count = remaining.len().min(buffer.len());
                    buffer[..count].copy_from_slice(&remaining[..count]);
                    self.position += count;
                    return Ok(count);
                }
                (Redirect::Ascii | Redirect::AsciiReportingTag, 0) => (1, buffer.len() / 2),
                (Redirect::Ascii | Redirect::AsciiReportingTag, _) => (0, buffer.len() / 2),
            };
            if units == 0 {
                return Ok(0);
            }
            if tag_units == 1 {
                buffer[..2].copy_from_slice(&0xFEFF_u16.to_le_bytes());
            }
            let count = remaining.len().min(units - tag_units);
            for (slot, byte) in buffer[2 * tag_units..]
                .chunks_exact_mut(2)
                .zip(&remaining[..count])
            {
                slot.copy_from_slice(&u16::from(*byte).to_le_bytes());
            }
            self.position += count;
            Ok(match self.redirect {
                Redirect::AsciiReportingTag => 2 * (count + tag_units),
                Redirect::Ascii | Redirect::Unicode => 2 * count,
            })
        }
    }

    /// A Shell console that types `script`, and counts how often its keystrokes are opened
    struct FakeConsole {
        text_input_ex: Result<bool, io::ErrorKind>,
        script: Vec<Keystroke>,
        opened: usize,
    }

    impl FakeConsole {
        fn new(text_input_ex: bool, script: Vec<Keystroke>) -> Self {
            Self {
                text_input_ex: Ok(text_input_ex),
                script,
                opened: 0,
            }
        }

        fn with_failing_gate(self) -> Self {
            Self {
                text_input_ex: Err(io::ErrorKind::Other),
                ..self
            }
        }
    }

    impl ShellConsole for FakeConsole {
        type Keystrokes = std::vec::IntoIter<io::Result<Keystroke>>;

        fn has_text_input_ex(&self) -> io::Result<bool> {
            self.text_input_ex.map_err(io::Error::from)
        }

        fn keystrokes(&mut self) -> io::Result<Self::Keystrokes> {
            self.opened += 1;
            Ok(self
                .script
                .iter()
                .copied()
                .map(Ok)
                .collect::<Vec<_>>()
                .into_iter())
        }
    }

    /// `text` as typed keystrokes: CR as Enter, every other character as itself
    fn typed(text: &str) -> Vec<Keystroke> {
        text.chars()
            .map(|character| match character {
                '\r' => Keystroke::Enter,
                character => Keystroke::Char(character),
            })
            .collect()
    }

    fn ok_keystrokes(script: &[Keystroke]) -> impl Iterator<Item = io::Result<Keystroke>> + '_ {
        script.iter().copied().map(Ok)
    }

    /// `text` in UCS-2, little-endian, after U+FEFF, as the Shell's `echo text >` writes it
    fn ucs2_file(text: &str) -> Vec<u8> {
        std::iter::once(0xFEFF)
            .chain(text.encode_utf16())
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// The secret that `-` reads from `stdin`, with no console behind it
    fn shell_secret(stdin: &mut FakeStdin, max_len: usize) -> Result<Secret, SecretError> {
        read_shell_secret(stdin, &mut FakeConsole::new(false, Vec::new()), max_len)
    }

    #[test]
    fn line_mode_removes_one_terminator() {
        for input in ["pw", "pw\n", "pw\r", "pw\r\n"] {
            let secret = read_secret_line(input.as_bytes(), PASSWORD_CAP)
                .unwrap_or_else(|error| panic!("{input:?}: {error}"));
            assert_eq!(secret.as_bytes(), b"pw", "{input:?}");
        }
    }

    #[test]
    fn line_mode_refuses_malformed_lines() {
        let cases: [(&[u8], &str); 12] = [
            (b"", "Empty"),
            (b"\n", "Empty"),
            (b"\r\n", "Empty"),
            (b"p\0w", "Nul"),
            (b"p\nw", "LineBreak"),
            (b"p\rw", "LineBreak"),
            (b"\npw", "LineBreak"),
            (b"pw\nxy\n", "LineBreak"),
            (b"pw\n\n", "LineBreak"),
            (b"pw\n\r", "LineBreak"),
            (b"123456789", "TooLong"),
            (b"123456789\r\n", "TooLong"),
        ];
        for (input, expected) in cases {
            let error = read_secret_line(input, 8).expect_err("a refused line");
            assert_eq!(kind(&error), expected, "{input:?}");
        }
        for input in [&b"12345678"[..], b"12345678\n", b"12345678\r\n"] {
            let secret = read_secret_line(input, 8)
                .unwrap_or_else(|error| panic!("{input:?} at the cap: {error}"));
            assert_eq!(secret.as_bytes(), b"12345678", "{input:?}");
        }
    }

    #[test]
    fn line_mode_reads_at_most_three_bytes_past_the_cap() {
        let mut reader = CountingReader::new(io::repeat(b'a'));
        let error = read_secret_line(&mut reader, PASSWORD_CAP).expect_err("an endless line");
        assert_eq!(kind(&error), "TooLong", "an endless line");
        assert!(
            reader.count <= PASSWORD_CAP + 3,
            "read {} bytes of an endless line",
            reader.count
        );

        let mut reader = CountingReader::new(&b"pw\r\n"[..]);
        read_secret_line(&mut reader, PASSWORD_CAP).expect("a short line");
        assert_eq!(reader.count, 4, "a short line is read whole");
    }

    #[test]
    fn line_mode_refuses_invalid_utf8() {
        for input in [&b"\xff\xfe"[..], b"p\xc3w", b"\xed\xa0\x80"] {
            let error = read_secret_line(input, PASSWORD_CAP).expect_err("invalid UTF-8");
            assert_eq!(kind(&error), "NotUtf8", "{input:?}");
        }
        let secret = read_secret_line("pä€😀".as_bytes(), PASSWORD_CAP).expect("UTF-8");
        assert_eq!(secret.as_bytes(), "pä€😀".as_bytes(), "UTF-8 kept");
    }

    #[test]
    fn line_mode_refuses_certificate_shaped_inputs() {
        let cases: [(&[u8], &str); 4] = [
            (b"\n", "Empty"),
            (b"\nAAAA", "LineBreak"),
            (b"\0AAAA", "Nul"),
            (b"AA\nBB", "LineBreak"),
        ];
        for (input, expected) in cases {
            let error =
                read_secret_line(input, CERTIFICATE_CAP).expect_err("a refused certificate");
            assert_eq!(kind(&error), expected, "{input:?}");
        }
        let page = [vec![b'A'; CERTIFICATE_CAP], b"\n".to_vec()].concat();
        let secret = read_secret_line(&page[..], CERTIFICATE_CAP).expect("a page");
        assert_eq!(secret.as_bytes(), &page[..CERTIFICATE_CAP], "a page");
    }

    #[test]
    fn file_mode_keeps_every_byte() {
        let input = b"\0key\r\n\nend\n";
        let secret = read_secret_file(&input[..], PASSWORD_CAP).expect("bytes");
        assert_eq!(secret.as_bytes(), input, "NUL and line breaks kept");

        let error = read_secret_file(&b""[..], PASSWORD_CAP).expect_err("empty");
        assert_eq!(kind(&error), "Empty", "empty");
    }

    #[test]
    fn file_mode_enforces_the_cap() {
        let secret = read_secret_file(&b"abcd"[..], 4).expect("at the cap");
        assert_eq!(secret.as_bytes(), b"abcd", "at the cap");

        let mut reader = CountingReader::new(io::repeat(b'a'));
        let error = read_secret_file(&mut reader, 4).expect_err("past the cap");
        assert_eq!(kind(&error), "TooLong", "past the cap");
        assert!(reader.count <= 5, "read {} bytes", reader.count);
    }

    #[test]
    fn caps_stop_at_64_kib() {
        let secret = read_secret_file(&b"pem"[..], 64 * 1024).expect("a 64 KiB cap");
        assert_eq!(secret.as_bytes(), b"pem", "a 64 KiB cap");
        read_secret_line(&b"pw"[..], 64 * 1024).expect("a 64 KiB line cap");
        read_typed_secret(ok_keystrokes(&typed("pw\r")), 64 * 1024).expect("a 64 KiB typed cap");

        let mut reader = CountingReader::new(&b"pem"[..]);
        let error = read_secret_file(&mut reader, 64 * 1024 + 1).expect_err("over 64 KiB");
        assert_eq!(kind(&error), "CapTooLarge", "file cap over 64 KiB");
        let error = read_secret_line(&mut reader, usize::MAX).expect_err("usize::MAX");
        assert_eq!(kind(&error), "CapTooLarge", "line cap usize::MAX");
        assert_eq!(reader.count, 0, "nothing read under a cap over 64 KiB");
        let error = read_typed_secret(ok_keystrokes(&typed("pw\r")), 64 * 1024 + 1)
            .expect_err("typed cap over 64 KiB");
        assert_eq!(kind(&error), "CapTooLarge", "typed cap over 64 KiB");
        let mut stdin = FakeStdin::new(Redirect::Unicode, &ucs2_file("pw"));
        let error = shell_secret(&mut stdin, 64 * 1024 + 1).expect_err("shell cap over 64 KiB");
        assert_eq!(kind(&error), "CapTooLarge", "shell cap over 64 KiB");
        assert_eq!(stdin.reads, 0, "no ReadFile under a cap over 64 KiB");
    }

    #[test]
    fn readers_report_read_errors() {
        let error = read_secret_line(FailingReader, PASSWORD_CAP).expect_err("line");
        assert_eq!(kind(&error), "Read", "line");
        let error = read_secret_file(FailingReader, PASSWORD_CAP).expect_err("file");
        assert_eq!(kind(&error), "Read", "file");
        let keystrokes = [Ok(Keystroke::Char('p')), Err(io::Error::other("no key"))];
        let error = read_typed_secret(keystrokes, PASSWORD_CAP).expect_err("keystrokes");
        assert_eq!(kind(&error), "Read", "keystrokes");
    }

    #[test]
    fn readers_retry_interrupted_reads() {
        let secret = read_secret_line(InterruptedOnce::new(&b"pw\n"[..]), PASSWORD_CAP)
            .expect("line after Interrupted");
        assert_eq!(secret.as_bytes(), b"pw", "line after Interrupted");
        let secret = read_secret_file(InterruptedOnce::new(&b"pw\n"[..]), PASSWORD_CAP)
            .expect("file after Interrupted");
        assert_eq!(secret.as_bytes(), b"pw\n", "file after Interrupted");
    }

    #[test]
    fn readers_refuse_overreported_reads() {
        let error = read_secret_line(OverreportingReader, PASSWORD_CAP).expect_err("line");
        assert_eq!(kind(&error), "Read", "line");
        let error = read_secret_file(OverreportingReader, PASSWORD_CAP).expect_err("file");
        assert_eq!(kind(&error), "Read", "file");
    }

    #[test]
    fn buffers_keep_their_preallocated_capacity() {
        let line = read_secret_line(&b"pw\r\n"[..], PASSWORD_CAP).expect("line");
        assert_eq!(line.0.capacity(), PASSWORD_CAP + 3, "line mode");
        let file = read_secret_file(&b"pw"[..], PASSWORD_CAP).expect("file");
        assert_eq!(file.0.capacity(), PASSWORD_CAP + 1, "file mode");
        let typed = read_typed_secret(ok_keystrokes(&typed("pΩ\r")), PASSWORD_CAP).expect("typed");
        assert_eq!(typed.0.capacity(), PASSWORD_CAP, "typed");
        let mut stdin = FakeStdin::new(Redirect::Ascii, b"pw\n");
        let redirected = shell_secret(&mut stdin, PASSWORD_CAP).expect("redirected");
        assert_eq!(redirected.0.capacity(), PASSWORD_CAP + 3, "redirected");
        let encoded = encode_ucs2(&line, 16).expect("encoded");
        assert_eq!(encoded.0.capacity(), 32, "encoded");

        // Every buffer is a Secret, which holds Zeroizing: this fails to compile otherwise.
        let _: [&Zeroizing<Vec<u8>>; 5] = [&line.0, &file.0, &typed.0, &redirected.0, &encoded.0];
    }

    #[test]
    fn secret_shows_only_its_length() {
        let secret = read_secret_line(FIXTURE.as_bytes(), PASSWORD_CAP).expect("fixture");
        let len = FIXTURE.len();
        assert_eq!(
            format!("{secret:?}"),
            format!("Secret {{ len: {len}, .. }}"),
            "Debug"
        );
        assert_eq!(format!("{secret}"), format!("{len}-byte secret"), "Display");
        assert_eq!(
            format!("{:?}", Keystroke::Char('S')),
            "Char(..)",
            "Keystroke Debug"
        );
    }

    #[test]
    fn no_message_shows_the_secret() {
        let fixture = FIXTURE.as_bytes();
        let line = |suffix: &[u8]| read_secret_line(&[fixture, suffix].concat()[..], PASSWORD_CAP);
        let typed_then = |keystroke: Option<Keystroke>| {
            let script: Vec<Keystroke> = typed(FIXTURE).into_iter().chain(keystroke).collect();
            read_typed_secret(ok_keystrokes(&script), PASSWORD_CAP)
        };
        let unicode = |content: &[u8]| {
            shell_secret(
                &mut FakeStdin::new(Redirect::Unicode, content),
                PASSWORD_CAP,
            )
        };
        let fixture_ucs2 = ucs2_file(FIXTURE);
        let secret = line(b"").expect("fixture");
        let claim = StdinClaim::new();
        claim.claim().expect("first claim");
        let errors = [
            read_secret_line(FailingReader, PASSWORD_CAP),
            read_secret_file(fixture, usize::MAX),
            read_secret_line(&b""[..], PASSWORD_CAP),
            read_secret_line(fixture, 4),
            line(b"\0"),
            line(b"\n\n"),
            line(b"\xff"),
            typed_then(Some(Keystroke::Escape)),
            typed_then(Some(Keystroke::Other)),
            typed_then(None),
            claim.claim().map(|()| secret_placeholder()),
            Err(SecretError::StdinTerminal),
            read_shell_secret(
                &mut FakeStdin::new(Redirect::Unicode, &fixture_ucs2).with_file_size(None),
                &mut FakeConsole::new(false, typed(FIXTURE)),
                PASSWORD_CAP,
            ),
            shell_secret(
                &mut FakeStdin::new(Redirect::Unicode, &fixture_ucs2).with_file_size(Some(11)),
                PASSWORD_CAP,
            ),
            shell_secret(
                &mut FakeStdin::new(
                    Redirect::Unicode,
                    &[&fixture_ucs2[..], &fixture_ucs2[..]].concat(),
                )
                .with_file_size(Some(4)),
                PASSWORD_CAP,
            ),
            unicode(&[&fixture_ucs2[..], b"\0"].concat()),
            unicode(&fixture_ucs2[2..]),
            shell_secret(&mut FakeStdin::new(Redirect::Ascii, fixture), PASSWORD_CAP),
            unicode(&[&fixture_ucs2[..], &0xD800_u16.to_le_bytes()[..]].concat()),
            encode_ucs2(&secret, usize::MAX),
            encode_ucs2(&line("😀".as_bytes()).expect("non-BMP fixture"), 16),
            encode_ucs2(
                &line("\u{E000}".as_bytes()).expect("Private Use Area fixture"),
                16,
            ),
            encode_ucs2(&secret, 4),
        ];
        let errors: Vec<SecretError> = errors
            .into_iter()
            .enumerate()
            .map(|(index, result)| match result {
                Ok(_) => panic!("case {index} accepted"),
                Err(error) => error,
            })
            .collect();
        let kinds: BTreeSet<&str> = errors.iter().map(kind).collect();
        assert_eq!(kinds.len(), 23, "every variant once: {kinds:?}");

        let fixture_bytes = format!("{fixture:?}");
        let renderings = fixture_renderings();
        for error in &errors {
            for message in [format!("{error}"), format!("{error:?}")] {
                let lowercase = message.to_lowercase();
                assert!(
                    !message.contains(&fixture_bytes[1..fixture_bytes.len() - 1])
                        && !renderings
                            .iter()
                            .any(|rendering| lowercase.contains(rendering.as_str())),
                    "{}: {message}",
                    kind(error)
                );
            }
        }
    }

    /// How a message could show a part of FIXTURE, in lowercase: one of its characters, or the
    /// code point of one or one of its UTF-8 bytes in hexadecimal, as U+XXXX or 0xXX
    fn fixture_renderings() -> Vec<String> {
        let values = FIXTURE
            .chars()
            .map(u32::from)
            .chain(FIXTURE.bytes().map(u32::from));
        FIXTURE
            .chars()
            .map(|character| character.to_lowercase().collect())
            .chain(values.flat_map(|value| {
                [
                    format!("u+{value:04x}"),
                    format!("0x{value:02x}"),
                    format!("0x{value:04x}"),
                ]
            }))
            .collect()
    }

    /// A secret for results that must be errors
    fn secret_placeholder() -> Secret {
        read_secret_line(&b"unused"[..], PASSWORD_CAP).expect("placeholder")
    }

    #[test]
    fn enter_ends_typing() {
        let script = typed("pw\rx\r");
        let mut keystrokes = ok_keystrokes(&script);
        let secret = read_typed_secret(&mut keystrokes, PASSWORD_CAP).expect("typed");
        assert_eq!(secret.as_bytes(), b"pw", "up to Enter");
        assert_eq!(keystrokes.count(), 2, "nothing read past Enter");

        let error =
            read_typed_secret(ok_keystrokes(&typed("\r")), PASSWORD_CAP).expect_err("Enter alone");
        assert_eq!(kind(&error), "Empty", "Enter alone");
        let error =
            read_typed_secret(ok_keystrokes(&typed("pw")), PASSWORD_CAP).expect_err("no Enter");
        assert_eq!(kind(&error), "KeystrokesEnded", "no Enter");
    }

    #[test]
    fn backspace_deletes_the_last_character() {
        let cases: [(&str, Vec<Keystroke>, &str); 3] = [
            (
                "after ASCII",
                [typed("pwx"), vec![Keystroke::Backspace], typed("\r")].concat(),
                "pw",
            ),
            (
                "with nothing typed",
                [vec![Keystroke::Backspace], typed("p\r")].concat(),
                "p",
            ),
            (
                "after 4- and 2-byte characters",
                [typed("pΩ😀"), vec![Keystroke::Backspace; 2], typed("w\r")].concat(),
                "pw",
            ),
        ];
        for (name, script, expected) in cases {
            let secret = read_typed_secret(ok_keystrokes(&script), PASSWORD_CAP)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(secret.as_bytes(), expected.as_bytes(), "{name}");
        }
    }

    #[test]
    fn esc_aborts_typing() {
        let script = [typed("pw"), vec![Keystroke::Escape], typed("\r")].concat();
        let error = read_typed_secret(ok_keystrokes(&script), PASSWORD_CAP).expect_err("Esc");
        assert_eq!(kind(&error), "Aborted", "Esc");
    }

    #[test]
    fn typing_refuses_other_keys_and_line_breaks() {
        let cases: [(Vec<Keystroke>, &str); 3] = [
            (
                [typed("p"), vec![Keystroke::Other], typed("\r")].concat(),
                "UnsupportedKey",
            ),
            (typed("p\nw\r"), "LineBreak"),
            (typed("p\0w\r"), "Nul"),
        ];
        for (script, expected) in cases {
            let error =
                read_typed_secret(ok_keystrokes(&script), PASSWORD_CAP).expect_err(expected);
            assert_eq!(kind(&error), expected, "{expected}");
        }
    }

    #[test]
    fn typing_counts_utf8_bytes_against_the_cap() {
        let secret = read_typed_secret(ok_keystrokes(&typed("Ωa\r")), 3).expect("3 bytes");
        assert_eq!(secret.as_bytes(), "Ωa".as_bytes(), "3 bytes at cap 3");

        for text in ["abcd", "ΩΩ", "a€"] {
            let script = [typed(text), typed("\r")].concat();
            let mut keystrokes = ok_keystrokes(&script);
            let error = read_typed_secret(&mut keystrokes, 3).expect_err("past the cap");
            assert_eq!(kind(&error), "TooLong", "{text}");
            assert_eq!(
                keystrokes.count(),
                1,
                "{text}: refused at the byte past the cap, before Enter"
            );
        }
    }

    #[test]
    fn redirect_reader_reads_ascii_through_a() {
        for content in [&b"pw\n"[..], b"pw", b"pw\r\n"] {
            let mut stdin = FakeStdin::new(Redirect::Ascii, content);
            let secret = shell_secret(&mut stdin, PASSWORD_CAP)
                .unwrap_or_else(|error| panic!("{content:?}: {error}"));
            assert_eq!(secret.as_bytes(), b"pw", "{content:?}");
            assert_eq!(stdin.reads, 2, "{content:?}: one read, then an empty one");
        }
        let mut stdin = FakeStdin::new(Redirect::AsciiReportingTag, b"pw\n");
        let secret = shell_secret(&mut stdin, PASSWORD_CAP).expect("a report of 2F+2");
        assert_eq!(secret.as_bytes(), b"pw", "a report of 2F+2");
    }

    #[test]
    fn redirect_reader_reads_ucs2_files_and_pipes() {
        for text in ["pw", "pw\n", "pw\r\n", "pä€😀\r\n"] {
            let mut stdin = FakeStdin::new(Redirect::Unicode, &ucs2_file(text));
            let secret = shell_secret(&mut stdin, PASSWORD_CAP)
                .unwrap_or_else(|error| panic!("{text:?}: {error}"));
            assert_eq!(secret.as_bytes(), text.trim_end().as_bytes(), "{text:?}");
            assert_eq!(stdin.reads, 2, "{text:?}: one read, then an empty one");
        }
    }

    #[test]
    fn redirect_reader_refuses_malformed_streams() {
        let pw = ucs2_file("pw\n");
        let cases: [(&str, FakeStdin, &str); 9] = [
            (
                "8 bytes read for FileSize 5",
                FakeStdin::new(Redirect::Unicode, &pw).with_file_size(Some(5)),
                "UnexpectedReadSize",
            ),
            (
                "8 bytes read for FileSize 7",
                FakeStdin::new(Redirect::Unicode, &pw).with_file_size(Some(7)),
                "UnexpectedReadSize",
            ),
            (
                "data past FileSize",
                FakeStdin::new(Redirect::Unicode, &[&pw[..], &pw[..]].concat())
                    .with_file_size(Some(2)),
                "LongerThanFileSize",
            ),
            (
                "odd UCS-2",
                FakeStdin::new(Redirect::Unicode, &pw[..pw.len() - 1]),
                "OddLength",
            ),
            (
                "even ASCII through <",
                FakeStdin::new(Redirect::Unicode, b"pw\r\n"),
                "NoByteOrderMark",
            ),
            (
                "odd ASCII through <",
                FakeStdin::new(Redirect::Unicode, b"pw\n"),
                "NoByteOrderMark",
            ),
            (
                "UCS-2 without U+FEFF",
                FakeStdin::new(Redirect::Unicode, &pw[2..]),
                "NoByteOrderMark",
            ),
            (
                "UTF-8 through <a",
                FakeStdin::new(Redirect::Ascii, "pä\n".as_bytes()),
                "NotAscii",
            ),
            (
                "unpaired low surrogate",
                FakeStdin::new(
                    Redirect::Unicode,
                    &[&ucs2_file("p")[..], &0xDC00_u16.to_le_bytes()[..]].concat(),
                ),
                "UnpairedSurrogate",
            ),
        ];
        for (name, mut stdin, expected) in cases {
            let error = shell_secret(&mut stdin, PASSWORD_CAP).expect_err(name);
            assert_eq!(kind(&error), expected, "{name}");
        }

        let secret = shell_secret(
            &mut FakeStdin::new(Redirect::Unicode, &ucs2_file("pä\n")),
            PASSWORD_CAP,
        )
        .expect("non-ASCII through <");
        assert_eq!(secret.as_bytes(), "pä".as_bytes(), "non-ASCII through <");
    }

    #[test]
    fn redirect_reader_bounds_the_file_size_before_reading() {
        // U+FEFF and max_len+3 CHAR16s
        let bound = 2 * (8 + 3) + 2;
        let content = ucs2_file("12345678\r\n");
        for (file_size, expected, reads) in [
            (bound + 1, "TooLong", 0),
            (0, "Empty", 0),
            (bound, "UnexpectedReadSize", 2),
        ] {
            let mut stdin = FakeStdin::new(Redirect::Unicode, &content)
                .with_file_size(Some(u64::try_from(file_size).expect("file size as u64")));
            let error = shell_secret(&mut stdin, 8).expect_err(expected);
            assert_eq!(kind(&error), expected, "FileSize {file_size}");
            assert_eq!(stdin.reads, reads, "FileSize {file_size}: ReadFile calls");
        }
        let mut stdin = FakeStdin::new(Redirect::Unicode, &content);
        let secret = shell_secret(&mut stdin, 8).expect("the cap and CRLF");
        assert_eq!(secret.as_bytes(), b"12345678", "the cap and CRLF");
    }

    #[test]
    fn redirect_reader_counts_utf8_bytes_against_the_cap() {
        let secret = shell_secret(
            &mut FakeStdin::new(Redirect::Unicode, &ucs2_file("Ωa\n")),
            3,
        )
        .expect("3 bytes");
        assert_eq!(secret.as_bytes(), "Ωa".as_bytes(), "3 bytes at cap 3");
        for text in ["ΩΩ", "😀", "abcd\n"] {
            let error = shell_secret(&mut FakeStdin::new(Redirect::Unicode, &ucs2_file(text)), 3)
                .expect_err("past the cap");
            assert_eq!(kind(&error), "TooLong", "{text:?}");
        }
    }

    #[test]
    fn console_gate_needs_simple_text_input_ex() {
        let mut stdin = FakeStdin::new(Redirect::Unicode, b"").with_file_size(None);
        let mut console = FakeConsole::new(false, typed("pw\r"));
        let error =
            read_shell_secret(&mut stdin, &mut console, PASSWORD_CAP).expect_err("no console");
        assert_eq!(
            kind(&error),
            "StdinUnreadable",
            "no file info, no SimpleTextInputEx"
        );
        assert_eq!((console.opened, stdin.reads), (0, 0), "nothing read");

        let mut console = FakeConsole::new(true, typed("pw\r"));
        let secret = read_shell_secret(&mut stdin, &mut console, PASSWORD_CAP).expect("console");
        assert_eq!(secret.as_bytes(), b"pw", "typed at the console");
        assert_eq!(
            (console.opened, stdin.reads),
            (1, 0),
            "keystrokes, no ReadFile"
        );

        let mut stdin = FakeStdin::new(Redirect::Ascii, b"pw\n");
        let mut console = FakeConsole::new(true, typed("typed\r"));
        let secret = read_shell_secret(&mut stdin, &mut console, PASSWORD_CAP).expect("redirect");
        assert_eq!(secret.as_bytes(), b"pw", "a redirect wins over the console");
        assert_eq!(console.opened, 0, "no keystrokes under a redirect");

        let mut stdin = FakeStdin::new(Redirect::Ascii, b"pw\n").with_failing_file_size();
        let mut console = FakeConsole::new(true, typed("typed\r"));
        let error = read_shell_secret(&mut stdin, &mut console, PASSWORD_CAP)
            .expect_err("a failing file size");
        assert_eq!(kind(&error), "Read", "a failing file size");
        assert_eq!(
            (console.opened, stdin.reads),
            (0, 0),
            "a failing file size: nothing read"
        );

        let mut stdin = FakeStdin::new(Redirect::Unicode, b"").with_file_size(None);
        let mut console = FakeConsole::new(true, typed("pw\r")).with_failing_gate();
        let error =
            read_shell_secret(&mut stdin, &mut console, PASSWORD_CAP).expect_err("a failing gate");
        assert_eq!(kind(&error), "Read", "a failing gate");
        assert_eq!(
            (console.opened, stdin.reads),
            (0, 0),
            "a failing gate: nothing read"
        );
    }

    #[test]
    fn ucs2_encoder_pads_with_nul() {
        let secret = read_secret_line("pΩ".as_bytes(), PASSWORD_CAP).expect("secret");
        let cases: [(usize, &[u8]); 3] = [
            (2, b"p\0\xa9\x03"),
            (3, b"p\0\xa9\x03\0\0"),
            (5, b"p\0\xa9\x03\0\0\0\0\0\0"),
        ];
        for (units, expected) in cases {
            let encoded =
                encode_ucs2(&secret, units).unwrap_or_else(|error| panic!("{units}: {error}"));
            assert_eq!(encoded.as_bytes(), expected, "{units} CHAR16s");
        }
        let encoded = encode_ucs2(&secret, MAX_UCS2_UNITS).expect("the largest buffer");
        assert_eq!(
            encoded.as_bytes().len(),
            2 * MAX_UCS2_UNITS,
            "the largest buffer"
        );
    }

    #[test]
    fn ucs2_encoder_refuses_what_ucs2_cannot_hold() {
        let secret = read_secret_line("pΩ".as_bytes(), PASSWORD_CAP).expect("secret");
        let error = encode_ucs2(&secret, 1).expect_err("over-long");
        assert_eq!(kind(&error), "TooManyCharacters", "over-long");
        let error = encode_ucs2(&secret, MAX_UCS2_UNITS + 1).expect_err("buffer over the limit");
        assert_eq!(kind(&error), "Ucs2BufferTooLarge", "buffer over the limit");

        let emoji = read_secret_line("p😀".as_bytes(), PASSWORD_CAP).expect("non-BMP secret");
        let error = encode_ucs2(&emoji, 16).expect_err("non-BMP");
        assert_eq!(kind(&error), "OutsideBmp", "non-BMP");

        let raw = read_secret_file(&b"\xff\xfe"[..], PASSWORD_CAP).expect("raw bytes");
        let error = encode_ucs2(&raw, 16).expect_err("not UTF-8");
        assert_eq!(kind(&error), "NotUtf8", "not UTF-8");
        let raw = read_secret_file(&b"p\0w"[..], PASSWORD_CAP).expect("raw bytes with NUL");
        let error = encode_ucs2(&raw, 16).expect_err("NUL");
        assert_eq!(kind(&error), "Nul", "NUL");
    }

    #[test]
    fn ucs2_encoder_refuses_the_private_use_area() {
        let encode = |character: char| {
            let secret = read_secret_line(format!("p{character}").as_bytes(), PASSWORD_CAP)
                .unwrap_or_else(|error| panic!("{character:?}: {error}"));
            encode_ucs2(&secret, 2)
        };
        for character in ['\u{E000}', '\u{F620}', '\u{F8FF}'] {
            let error = encode(character).expect_err("Private Use Area");
            assert_eq!(kind(&error), "PrivateUse", "{character:?}");
        }
        for character in ['\u{D7FF}', '\u{F900}'] {
            let encoded =
                encode(character).unwrap_or_else(|error| panic!("{character:?}: {error}"));
            let unit = u16::try_from(u32::from(character)).expect("a BMP character");
            assert_eq!(
                encoded.as_bytes(),
                [&b"p\0"[..], &unit.to_le_bytes()].concat(),
                "{character:?}"
            );
        }
    }

    #[test]
    fn secrets_compare_in_constant_time() {
        let secret = |text: &str| read_secret_line(text.as_bytes(), PASSWORD_CAP).expect(text);
        let cases = [
            ("pw", "pw", true),
            ("pw", "pW", false),
            ("pw", "pw2", false),
        ];
        for (left, right, equal) in cases {
            assert_eq!(
                bool::from(secret(left).ct_eq(&secret(right))),
                equal,
                "{left} = {right}"
            );
        }
    }

    #[test]
    fn stdin_gives_one_secret() {
        let claim = StdinClaim::new();
        claim.claim().expect("the first -");
        let error = claim.claim().expect_err("a second -");
        assert_eq!(kind(&error), "StdinClaimed", "a second -");
    }
}
