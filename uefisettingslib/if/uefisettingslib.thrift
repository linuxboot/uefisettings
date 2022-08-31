enum Backend {
  Unknown = 0,
  Hii = 1,
  Ilo = 2,
}

// --- Backend: auto ---

struct MachineInfo {
  1: set<Backend> backend;
  2: string bios_vendor;
  3: string bios_version;
  4: string bios_release;
  5: string bios_date;
  6: string product_name;
  7: string product_family;
  8: string product_version;
}

struct Question {
  1: string name;
  2: string answer;
  3: list<string> options;
  4: string help;
}

struct SetResponse {
  // selector values:
  // hii - the selector will be the packagelist (TODO: change to form@packagelist).
  // ilo - the selector will be iloname-endpoint (for example ilo5-bios or ilo5-debug).
  1: string selector;

  2: Backend backend;
  3: Question question; // this will be the newly modified question
  4: bool modified;
  5: bool is_translated; // is the question/answer in the spellings database
}

struct GetResponse {
  1: string selector;
  2: Backend backend;
  3: Question question;
  4: bool is_translated; // is the question/answer in the spellings database
}

struct Error {
  1: string error_message;
}

// --- Backend: ilo ---

struct IloAttributes {
  1: string selector;
  2: map<string, string> attributes;
}

// --- Backend: hii ---

struct HiiShowIfrResponse {
  1: string readable_representation;
}

struct HiiDatabase {
  1: binary db;
}

struct HiiStringsPackage {
  1: string package_list; // note that this isn't unique, multiple packages will be part of the same package list
  2: map<i32, string> string_package;
}
