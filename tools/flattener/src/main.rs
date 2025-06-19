use clap::Parser;
use regex::Regex;
use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{self, BufReader, prelude::*};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    input: String,

    #[arg(short, long)]
    output: String,

    includes: Vec<String>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let mut included = HashSet::new();
    let mut lines = read_lines(&PathBuf::from(&cli.input))?;
    let mut output = File::create(&cli.output)?;
    let re = Regex::new(r##"#include \"(.+)\""##).unwrap();

    while !lines.is_empty() {
        let line = lines.pop_front().unwrap();

        let mut processed = false;
        if let Some(caps) = re.captures(&line) {
            let included_file = caps.get(1).unwrap().as_str().to_string();
            if included.contains(&included_file) {
                lines.push_front(format!(
                    "/* {} has already been included. */",
                    included_file
                ));
                processed = true;
            } else if let Some(path) = find_file(&included_file, &cli.includes) {
                lines.push_front(format!("/* End of {} */", included_file));
                for line in read_lines(&path)?.into_iter().rev() {
                    lines.push_front(line);
                }
                lines.push_front(format!("/* Start of {} */", included_file));
                included.insert(included_file);
                processed = true;
            } else {
                println!("Cannot find {}, skipping", included_file);
            }
        }

        if !processed {
            writeln!(&mut output, "{}", line)?;
        }
    }

    Ok(())
}

fn find_file(file: &str, includes: &[String]) -> Option<PathBuf> {
    for include in includes {
        let path = Path::new(&include).join(file);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn read_lines(file: &PathBuf) -> io::Result<VecDeque<String>> {
    let file = File::open(file)?;
    let reader = BufReader::new(file);

    let mut result = VecDeque::new();
    for line in reader.lines() {
        result.push_back(line?.trim_end_matches("\n").to_string());
    }
    Ok(result)
}
