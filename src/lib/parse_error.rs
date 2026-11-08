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

//! The error of a binrw read as uefisettings shows it. binrw's Display prints a backtrace frame
//! per field being parsed, each on lines of its own with the Rust source location of its derive
//! (binrw 0.13.3 src/error/backtrace.rs), which error_message and logs would show.

use std::fmt;
use std::fmt::Write;
use std::io::Read;
use std::io::Seek;

use binrw::error::BacktraceFrame;
use binrw::BinRead;
use binrw::BinReaderExt;

/// A binrw read that failed. Display gives it on one line: the error, then the messages of its
/// backtrace frames, the fields being parsed, innermost first. Debug keeps binrw's text:
/// `{:#?}` of an anyhow::Error holding it shows binrw's frames, with their source locations.
pub struct ParseError(binrw::Error);

impl ParseError {
    /// Whether the read ran out of bytes.
    pub fn is_eof(&self) -> bool {
        self.0.is_eof()
    }

    /// The error that the frames lead to.
    pub fn root_cause(&self) -> &binrw::Error {
        self.0.root_cause()
    }
}

impl From<binrw::Error> for ParseError {
    fn from(error: binrw::Error) -> Self {
        Self(error)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_on_one_line(&self.0, &mut OneLine(f))
    }
}

impl fmt::Debug for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl std::error::Error for ParseError {}

/// Writes `error` to `out`: a backtrace's error, then its frames' messages in parentheses; the
/// error of each variant of an enum after a semicolon.
fn write_on_one_line(error: &binrw::Error, out: &mut impl Write) -> fmt::Result {
    match error {
        binrw::Error::Backtrace(backtrace) => {
            write_on_one_line(&backtrace.error, out)?;
            for (index, frame) in backtrace.frames.iter().enumerate() {
                out.write_str(match index {
                    0 => " (",
                    _ => "; ",
                })?;
                match frame {
                    BacktraceFrame::Full { message, .. } | BacktraceFrame::Message(message) => {
                        out.write_str(message)?;
                    }
                    BacktraceFrame::Custom(context) => write!(out, "{context}")?,
                }
            }
            match backtrace.frames.is_empty() {
                true => Ok(()),
                false => out.write_str(")"),
            }
        }
        binrw::Error::EnumErrors {
            pos,
            variant_errors,
        } => {
            write!(out, "no variants matched at {pos:#x}")?;
            for (name, error) in variant_errors {
                write!(out, "; {name}: ")?;
                write_on_one_line(error, out)?;
            }
            Ok(())
        }
        // one line in binrw 0.13.3, but for the texts that they hold, which OneLine joins
        error => write!(out, "{error}"),
    }
}

/// A formatter that writes each line break as a space.
struct OneLine<'a, 'b>(&'a mut fmt::Formatter<'b>);

impl Write for OneLine<'_, '_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut lines = text.split('\n');
        if let Some(first) = lines.next() {
            self.0.write_str(first)?;
        }
        for line in lines {
            self.0.write_str(" ")?;
            self.0.write_str(line)?;
        }
        Ok(())
    }
}

/// binrw's reads, failing with ParseError.
pub trait ReadParsed: Read + Seek + Sized {
    /// BinReaderExt::read_ne.
    fn parse_ne<'a, T>(&mut self) -> Result<T, ParseError>
    where
        T: BinRead,
        T::Args<'a>: Default,
    {
        self.parse_ne_args(<T::Args<'a> as Default>::default())
    }

    /// BinReaderExt::read_le.
    #[expect(clippy::disallowed_methods, reason = "the read that ParseError wraps")]
    fn parse_le<'a, T>(&mut self) -> Result<T, ParseError>
    where
        T: BinRead,
        T::Args<'a>: Default,
    {
        Ok(self.read_le_args(<T::Args<'a> as Default>::default())?)
    }

    /// BinReaderExt::read_ne_args.
    #[expect(clippy::disallowed_methods, reason = "the read that ParseError wraps")]
    fn parse_ne_args<T: BinRead>(&mut self, args: T::Args<'_>) -> Result<T, ParseError> {
        Ok(self.read_ne_args(args)?)
    }
}

impl<R: Read + Seek> ReadParsed for R {}

#[cfg(test)]
mod tests {
    use super::*;

    /// An enum's variant whose error is a backtrace gives its frames' messages, without their
    /// source locations, on one line.
    #[test]
    fn enum_variant_backtraces_render_without_source_paths() {
        let frame = BacktraceFrame::Full {
            code: None,
            message: "While parsing field 'f' in A".into(),
            file: "src/lib/frame.rs",
            line: 7,
        };
        let variant = binrw::Error::Backtrace(binrw::error::Backtrace::new(
            binrw::Error::Io(std::io::ErrorKind::UnexpectedEof.into()),
            vec![frame],
        ));
        let error = ParseError::from(binrw::Error::EnumErrors {
            pos: 0x4,
            variant_errors: vec![("A", variant)],
        });

        assert_eq!(
            error.to_string(),
            "no variants matched at 0x4; A: unexpected end of file (While parsing field 'f' in A)",
            "{error:?}"
        );
    }

    /// The errors of an enum's variants follow its own after semicolons, and a line break in a
    /// message becomes a space: the text stays one line.
    #[test]
    fn enum_errors_and_line_breaks_render_on_one_line() {
        let error = ParseError::from(binrw::Error::EnumErrors {
            pos: 0x10,
            variant_errors: vec![
                (
                    "First",
                    binrw::Error::AssertFail {
                        pos: 0x10,
                        message: "two\nlines".to_string(),
                    },
                ),
                ("Second", binrw::Error::NoVariantMatch { pos: 0x12 }),
            ],
        });

        assert_eq!(
            error.to_string(),
            "no variants matched at 0x10; First: two lines at 0x10; Second: no variants matched \
             at 0x12",
            "{error:?}"
        );
    }

    /// A user-specified context frame gives its Display, on one line.
    #[test]
    fn custom_frames_render_on_one_line() {
        let error = ParseError::from(binrw::Error::Backtrace(binrw::error::Backtrace::new(
            binrw::Error::Io(std::io::ErrorKind::UnexpectedEof.into()),
            vec![BacktraceFrame::Custom(Box::new("custom\ncontext"))],
        )));

        assert_eq!(
            error.to_string(),
            "unexpected end of file (custom context)",
            "{error:?}"
        );
    }

    /// root_cause and is_eof look through the backtrace frames to the error that they lead to.
    #[test]
    fn root_cause_and_is_eof_look_through_frames() {
        let error = ParseError::from(binrw::Error::Backtrace(binrw::error::Backtrace::new(
            binrw::Error::AssertFail {
                pos: 0x2,
                message: "assert".to_string(),
            },
            vec![BacktraceFrame::Message(
                "While parsing field 'f' in A".into(),
            )],
        )));

        assert!(
            matches!(
                error.root_cause(),
                binrw::Error::AssertFail { pos: 0x2, .. }
            ),
            "{error:?}"
        );
        assert!(!error.is_eof(), "{error:?}");
    }
}
