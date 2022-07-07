// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use anyhow::Context;
use log::info;

use anyhow::Result;
use clap::Parser;
use clap::Subcommand;

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

    #[clap(short, long, parse(from_occurrences))]
    debug: usize,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // TODO: dumpdb,showifr,questions,change,liststrings
    ListStrings {},
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    match &args.command {
        Commands::ListStrings {} => {
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
                    panic!("File size is too big for the file to be a HII database.");
                }

                let mut file_contents = Vec::new();
                match file.read_to_end(&mut file_contents) {
                    Err(why) => panic!("Couldn't convert file bytes to Vec<u8> : {}", why),
                    _ => (),
                };

                for (guid, package_list) in (package::read_db(&file_contents))?.strings {
                    println!("Packagelist {}", guid);
                    for string_package in package_list {
                        println!("- New String Package");
                        for (string_id_current, string_current) in string_package {
                            println!("{} : \"{}\"", string_id_current, string_current);
                        }
                    }
                }
            } else {
                println!("Please provide the database dump.")
            }
            // TODO: Otherwise try to extract it
        }
    }

    info!("Exiting UEFI Settings Manipulation Tool");
    Ok(())
}
