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

//! The guest of hii.rs, whose PlatformLang this test sets to fr-FR first: list-questions shows
//! DriverSample's texts in the platform language unless --language states another (UEFI 2.11
//! §33.2.6).

use uefisettings_qemu_guest::driver_sample::ONE_OF_PROMPT;
use uefisettings_qemu_guest::driver_sample::ONE_OF_PROMPT_FR_FR;
use uefisettings_qemu_guest::global_variable;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::Question;

#[test]
fn texts_show_in_the_platform_language_or_the_stated_one() {
    let set = uefisettings(&["variable", "set", "PlatformLang", "fr-FR"]);
    assert_eq!(set.code, Some(0), "set PlatformLang fr-FR: {set:#?}");
    assert_eq!(
        global_variable("PlatformLang").as_deref(),
        Some(&b"fr-FR\0"[..]),
        "PlatformLang"
    );

    for (flags, shown, hidden) in [
        (&[][..], ONE_OF_PROMPT_FR_FR, ONE_OF_PROMPT),
        (
            &["--language", "en-US"][..],
            ONE_OF_PROMPT,
            ONE_OF_PROMPT_FR_FR,
        ),
    ] {
        let questions: Vec<Question> =
            json(&[&["hii", "list-questions", "--json"][..], flags].concat());
        let names: Vec<&str> = questions
            .iter()
            .map(|question| question.name.as_str())
            .collect();
        assert!(
            names.contains(&shown),
            "{flags:?}: {shown:?} is not listed: {names:?}"
        );
        assert!(
            !names.contains(&hidden),
            "{flags:?}: {hidden:?} is listed: {names:?}"
        );
    }
}
