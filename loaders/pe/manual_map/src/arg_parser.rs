use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "nitinol", disable_help_subcommand = true)]
pub struct Args {
    /// Path to the PE to run
    #[arg(short = 'p', long = "pe", value_name = "FILE")]
    pub pe: String,

    /// Export name (for DLL)
    #[arg(long = "export", value_name = "NAME")]
    pub export: Option<String>,

    /// Everything after --param is forwarded to the loaded PE
    ///
    /// Example:
    ///   nitinol --pe mimikatz.exe --param coffee exit
    #[arg(
        long = "param",
        num_args = 0..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub param: Vec<String>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
