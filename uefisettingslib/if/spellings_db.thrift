namespace py3 hardware.uefiset.translations
namespace cpp2 hardware.uefiset.translations

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
