mod app;
mod cli;
mod hsm;
mod pki;
mod store;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();
    if let Err(err) = app::run(cli) {
        app::print_error_and_exit(err);
    }
}
