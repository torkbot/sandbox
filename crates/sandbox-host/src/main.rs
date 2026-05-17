use std::env;
use std::process::ExitCode;

const USAGE: &str = "usage: sandbox-host --capabilities";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("--capabilities"), None) => {
            print_capabilities();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn print_capabilities() {
    println!(
        concat!(
            "{{",
            "\"schemaVersion\":1,",
            "\"vmHost\":true,",
            "\"controlTransport\":\"unix-fd\",",
            "\"hypervisorEntitlementProcess\":true",
            "}}"
        )
    );
}
