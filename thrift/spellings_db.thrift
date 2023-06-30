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

namespace py3 hardware.uefisettings.translations
namespace cpp2 hardware.uefisettings.translations

// Hii and HPE/Ilo have different spellings for the same questions/attributes and their answers.
// Different OCP vendors also have their own version spellings as well.
// This file aims to have one canonical spelling for each common setting and then map it to different spellings.

struct QuestionMapping {
  1: optional HiiQuestion hii_question;
  2: optional IloQuestion ilo_question;
}

struct HiiQuestion {
  1: list<string> question_variations; // multiple variations to try to get question
  2: optional map<string, list<string>> answer_replacements; // ex map Enabled -> [Enabled, Enable] before trying to set
}

struct IloQuestion {
  1: string question; // the correct variation of that spelling for Redfish
  2: optional map<string, string> answer_replacements; // ex rename Enabled -> PresentEnabled before trying to set
}

// Canonical Question Names
// These are defined as constants so its eazy to change them once here instead of changing them everywhere in tooling
const string CQ_TPM_STATE = "TPM State";
const string CQ_SECURITY_DEVICE_SUPPORT = "Security Device Support";
const string CQ_HYPER_THREADING = "Hyper Threading";
const string CQ_TXT_SUPPORT = "TXT Support";
const string CQ_VT_D = "VTd";

const map<string, QuestionMapping> translation_db = {
  CQ_TPM_STATE: QuestionMapping{
    hii_question = HiiQuestion{
      question_variations = ["TPM State"],
      answer_replacements = {
        "Enabled": ["Enabled", "Enable"],
        "Disabled": ["Disabled", "Disable"],
      },
    },
    ilo_question = IloQuestion{
      question = "TpmState",
      answer_replacements = {"Enabled": "PresentEnabled"},
    },
  },
  CQ_SECURITY_DEVICE_SUPPORT: QuestionMapping{
    hii_question = HiiQuestion{
      question_variations = ["Security Device Support"],
      answer_replacements = {
        "Enabled": ["Enabled", "Enable"],
        "Disabled": ["Disabled", "Disable"],
      },
    },
  },
  CQ_TXT_SUPPORT: QuestionMapping{
    hii_question = HiiQuestion{
      question_variations = ["TXT Support", "Enable Intel(R) TXT"],
      answer_replacements = {
        "Enabled": ["Enabled", "Enable"],
        "Disabled": ["Disabled", "Disable"],
      },
    },
    ilo_question = IloQuestion{question = "IntelTxt"},
  },
  CQ_HYPER_THREADING: QuestionMapping{
    hii_question = HiiQuestion{
      question_variations = [
        "Hyper-Threading",
        "Enable LP",
        "Hyper-Threading [ALL]",
      ],
      answer_replacements = {
        "Enabled": ["Enabled", "Enable"],
        "Disabled": ["Disabled", "Disable"],
      },
    },
  },
  CQ_VT_D: QuestionMapping{
    hii_question = HiiQuestion{
      question_variations = [
        "(VT-d)",
        "VT for Directed I/O",
        "Intel® VT for Directed I/O (VT-d)",
      ],
      answer_replacements = {
        "Enabled": ["Enabled", "Enable"],
        "Disabled": ["Disabled", "Disable"],
      },
    },
  },
};
