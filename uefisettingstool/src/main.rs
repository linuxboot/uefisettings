// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;

use log::info;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use clap::Subcommand;

use uefisettingslib::hii::extract;
use uefisettingslib::hii::forms;
use uefisettingslib::hii::package;

const MAX_ALLOWED_FILESIZE: u64 = 16 * 1024 * 1024;

#[derive(Parser)]
#[clap(
    name = "uefisettings",
    about = "UEFI Settings Manipulation Tool",
    long_about = None
)]
struct Args {
    /// Path to hii database dump
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    filename: Option<PathBuf>,

    /// Strings package language code
    lang: Option<String>,

    #[clap(short, long, value_parser)]
    question: Option<String>,

    #[clap(short, long, parse(from_occurrences))]
    debug: usize,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // TODO: change
    ListStrings {},
    ShowIfr {},
    Questions {},
    DumpDB {},
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    match &args.command {
        Commands::ListStrings {} => {
            let file_contents = get_db_dump_bytes(&args)?;

            for (guid, package_list) in (package::read_db(&file_contents))?.strings {
                println!("Packagelist {}", guid);
                for string_package in package_list {
                    println!("- New String Package");
                    for (string_id_current, string_current) in string_package {
                        println!("{} : \"{}\"", string_id_current, string_current);
                    }
                }
            }
        }
        Commands::ShowIfr {} => {
            let file_contents = get_db_dump_bytes(&args)?;
            let parsed_db = package::read_db(&file_contents)?;

            for (guid, package_list) in parsed_db.forms {
                println!("Packagelist {}", &guid);
                for form_package in package_list {
                    println!(
                        "{}",
                        forms::display(
                            form_package,
                            0,
                            parsed_db
                                .strings
                                .get(&guid)
                                .context("failed to get string packages using GUID")?
                        )?
                    )
                }
            }
        }

        Commands::Questions {} => {
            if let Some(question) = &args.question {
                let file_contents = get_db_dump_bytes(&args)?;
                let parsed_db = package::read_db(&file_contents)?;
                for (guid, package_list) in parsed_db.forms {
                    for form_package in package_list {
                        // string_phrases contains just one item (input from user) now, but eventually
                        // we plan to have a database which whill match similar string
                        let string_phrases = Vec::from([question.clone()]);

                        if let Some(answer) = forms::find_answer(
                            form_package,
                            parsed_db
                                .strings
                                .get(&guid)
                                .context("failed to get string packages using GUID")?,
                            &string_phrases,
                        ) {
                            println!("{:?}", answer);
                        } else {
                            println!("Question not found in Packagelist {}", &guid);
                        }
                    }
                }
            } else {
                return Err(anyhow!("Please provide the question."));
            }
        }

        Commands::DumpDB {} => {
            if let Some(dbdump_path) = args.filename.as_deref() {
                let mut file = File::create(dbdump_path)?;
                file.write_all(&extract::extract_db()?)?;
                println!("HiiDB written to {}", dbdump_path.display());
            } else {
                return Err(anyhow!("Please provide the filename."));
            }
        }
    }

    info!("Exiting UEFI Settings Manipulation Tool");
    Ok(())
}

fn get_db_dump_bytes(args: &Args) -> Result<Vec<u8>> {
    // If dbdump's path is provided use that
    if let Some(dbdump_path) = args.filename.as_deref() {
        info!("Using database dump from file: {}", dbdump_path.display());

        let mut file = File::open(&dbdump_path)
            .context(format!("opening dbdump from{}", dbdump_path.display()))?;

        // Most Hii DBs are afew hundred kilobytes in size and the largest we've seen so far is close to 3 MB.
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
        extract::extract_db()
    }
}
