mod utilities;

use anyhow::Result;
use clap::Parser;
use utilities::certcheck::print_certificate_info;

#[derive(Parser)]
#[command(author, version, about)]
struct Args {
    url: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    print_certificate_info(&args.url)?;

    Ok(())
}
