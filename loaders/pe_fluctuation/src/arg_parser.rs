use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "pe_fluctuation",
    about = "A manual PE loader with memory fluctuation evasion",
    after_help = "EXAMPLES:\n  pe_fluctuation.exe -p calc.exe\n  pe_fluctuation.exe  -p mimikatz.exe --param coffee exit"
)]
pub struct Args {
    /// Path to the PE to run
    #[arg(short = 'p', long = "pe", value_name = "FILE", required = true)]
    pub pe: String,

    /// Export name to execute (required if the PE is a DLL)
    #[arg(long = "export", value_name = "NAME")]
    pub export: Option<String>,

    /// Arguments to forward to the target PE. 
    /// All values after this flag are treated as target parameters.
    #[arg(
        long = "param",
        value_name = "ARGS",
        num_args = 0..,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "Forward arguments to the loaded PE (e.g., --param arg1 arg2)"
    )]
    pub param: Vec<String>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
