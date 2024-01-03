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

use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use fbthrift::simplejson_protocol;
use fbthrift::simplejson_protocol::Serializable;
use log::info;
use uefisettings_spellings_db_thrift::consts::translation_db;
use uefisettings::exports::identify_machine;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::IloBackend;
use uefisettings::exports::SettingsBackend;
use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::MachineInfo;

const MAX_ALLOWED_FILESIZE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[clap(
    name = "uefisettings",
    about = "UEFI Settings Manipulation Tool",
    long_about = None
)]
struct UefiSettingsToolArgs {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Commands which work on machines exposing the UEFI HiiDB
    Hii(HiiCommand),
    /// Commands which work on machines having HPE's Ilo BMC
    Ilo(IloCommand),
    // TODO: Auto(AutoCommand) after building a backend identifier function
    // TODO: Get/Set without having to specify Auto
    /// Auto-identify backend and display hardware/bios-information
    Identify {
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// Auto-identify backend and get the current value of a question
    Get {
        #[clap(value_parser)]
        question: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// Auto-identify backend and set/change the value of a question
    Set {
        #[clap(value_parser)]
        question: String,
        #[clap(value_parser)]
        value: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// Show the translation/spellings database for questions and answers
    ShowTranslations {
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
}

#[derive(Debug, Parser)]
struct HiiCommand {
    #[clap(subcommand)]
    command: HiiSubcommands,
}

#[derive(Debug, Subcommand)]
enum HiiSubcommands {
    /// Get the current value of a question
    Get {
        #[clap(value_parser)]
        question: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// Set/change the value of a question
    Set {
        #[clap(value_parser)]
        question: String,
        #[clap(value_parser)]
        value: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// Show a human readable representation of the Hii Forms
    ShowIFR {
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[clap(parse(from_os_str), short, long)]
        filename: Option<PathBuf>,
    },
    /// Dump HiiDB into a file
    ExtractDB {
        #[clap(parse(from_os_str))]
        filename: PathBuf,
    },
    /// List all strings-id, string pairs in HiiDB
    ListStrings {
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[clap(parse(from_os_str), short, long)]
        filename: Option<PathBuf>,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// List questions HiiDB. Note that these are not all possible questions, because we don't parse certain non-useful question types.
    ListQuestions {
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[clap(parse(from_os_str), short, long)]
        filename: Option<PathBuf>,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
}

#[derive(Debug, Parser)]
struct IloCommand {
    #[clap(subcommand)]
    command: IloSubcommands,
}

#[derive(Debug, Subcommand)]
enum IloSubcommands {
    /// Get the current value of a question
    Get {
        #[clap(value_parser)]
        question: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// Set/change the value of a question
    Set {
        #[clap(value_parser)]
        question: String,
        #[clap(value_parser)]
        value: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// List bios attributes and their current values
    ShowAttributes {
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// List all pending changes that will take effect after reboot
    ShowPendingAttributes {
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let args = UefiSettingsToolArgs::parse();

    if let Err(why) = handle_cmds(args) {
        print_with_style(
            uefisettings_backend_thrift::Error {
                error_message: format!("{:#}", why),
                ..Default::default()
            },
            true,
        );
        process::exit(1);
    }

    info!("Exiting UEFI Settings Manipulation Tool");
    Ok(())
}

fn handle_cmds(args: UefiSettingsToolArgs) -> Result<()> {
    match &args.command {
        Commands::Hii(hii_command) => match &hii_command.command {
            HiiSubcommands::Get { question, json } => {
                let res = HiiBackend::get(question, None)?;
                print_with_style(res, *json);
            }
            HiiSubcommands::Set {
                question,
                value,
                json,
            } => {
                let res = HiiBackend::set(question, value, None)?;
                print_with_style(res, *json);
            }
            HiiSubcommands::ShowIFR { filename } => {
                let res = HiiBackend::show_ifr(&get_db_dump_bytes(filename.as_deref())?)?;
                println!("{}", res.readable_representation);
            }
            HiiSubcommands::ExtractDB { filename } => {
                let mut file = File::create(filename)?;
                let res = HiiBackend::extract_db()?;
                file.write_all(&res.db)?;

                println!("{{\"info\": \"HiiDB written to {:?}\"}}", &filename);
            }
            HiiSubcommands::ListStrings { filename, json } => {
                let res = HiiBackend::list_strings(&get_db_dump_bytes(filename.as_deref())?)?;
                print_with_style(res, *json);
            }
            HiiSubcommands::ListQuestions { filename, json } => {
                let res = HiiBackend::list_questions(&get_db_dump_bytes(filename.as_deref())?)?;
                print_with_style(res, *json);
            }
        },
        Commands::Ilo(ilo_command) => match &ilo_command.command {
            IloSubcommands::Get { question, json } => {
                let res = IloBackend::get(question, None)?;
                print_with_style(res, *json);
            }
            IloSubcommands::Set {
                question,
                value,
                json,
            } => {
                let res = IloBackend::set(question, value, None)?;
                print_with_style(res, *json);
            }
            IloSubcommands::ShowAttributes { json } => {
                let res = IloBackend::show_attributes()?;
                print_with_style(res, *json);
            }
            IloSubcommands::ShowPendingAttributes { json } => {
                let res = IloBackend::show_pending_attributes()?;
                print_with_style(res, *json);
            }
        },
        Commands::Identify { json } => {
            let res = identify_machine()?;
            print_with_style(res, *json);
        }
        Commands::Get { question, json } => {
            let machine = identify_machine()?;
            if prioritize_backend(&machine, *json) == Backend::Ilo {
                let res = IloBackend::get(question, None)?;
                print_with_style(res, *json);
            } else {
                let res = HiiBackend::get(question, None)?;
                print_with_style(res, *json);
            }
        }
        Commands::Set {
            question,
            value,
            json,
        } => {
            let machine = identify_machine()?;
            if prioritize_backend(&machine, *json) == Backend::Ilo {
                let res = IloBackend::set(question, value, None)?;
                print_with_style(res, *json);
            } else {
                let res = HiiBackend::set(question, value, None)?;
                print_with_style(res, *json);
            }
        }
        Commands::ShowTranslations { json } => {
            print_with_style(&*translation_db, *json);
        }
    }
    Ok(())
}

fn prioritize_backend(machine: &MachineInfo, json: bool) -> Backend {
    if machine.backend.len() > 1 && !json {
        println!("Multiple backends found: {:#?}", machine.backend);
        println!("Using the Ilo backend");
    }
    // ilo is prioritized because its more structured than hii if there are multiple supported backends
    // identify_machine will error out if there are no backends so we can be sure that it has at least 1
    if machine.backend.contains(&Backend::Ilo) {
        Backend::Ilo
    } else {
        Backend::Hii
    }
}

fn get_db_dump_bytes(filename: Option<&Path>) -> Result<Vec<u8>> {
    // If dbdump's path is provided use that
    if let Some(dbdump_path) = filename {
        info!("Using database dump from file: {}", dbdump_path.display());

        let mut file = File::open(&dbdump_path)
            .context(format!("opening dbdump from{}", dbdump_path.display()))?;

        // Most Hii DBs are a few hundred kilobytes in size and the largest we've seen so far is close to 3 MB.
        // Since we're reading the entire DB into a Vec<u8> we need to have a check here.
        if file
            .metadata()
            .context("failed to read metadata for open file")?
            .len()
            > MAX_ALLOWED_FILESIZE
        {
            return Err(anyhow!(
                "File size is too big for the file to be a HII database."
            ));
        }

        let mut file_contents = Vec::new();
        file.read_to_end(&mut file_contents)
            .context("Couldn't convert file bytes to Vec<u8>")?;

        Ok(file_contents)
    } else {
        Ok(HiiBackend::extract_db()?.db)
    }
}

// print_with_style either prints as json or with rust's debug pretty-printer
fn print_with_style<T>(result: T, json: bool)
where
    T: Serializable + Debug,
{
    if json {
        let buf = simplejson_protocol::serialize(result);
        println!("{}", String::from_utf8_lossy(&buf));
    } else {
        println!("{:#?}", result);
    }
}
