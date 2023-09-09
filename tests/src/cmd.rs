use std::process::Command;

#[macro_export]
macro_rules! cmd {
    ($($cmd:expr) $(,)?) => {{
        let mut cmd = std::process::Command::new($cmd);
        let status =        cmd.status().unwrap();
    }}
    ($($cmd:expr) $(, $arg:expr)*) => {{
        let mut cmd = std::process::Command::new($cmd);
        $(
            cmd.arg($arg);
        )*
let status =        cmd.status().unwrap();

    }}
}

/*
pub fn cmd(args: impl IntoIterator<Item = impl core::fmt::Display>) -> Output {
    let mut args = args.into_iter();
    let mut cmd = Command::new(args.next().unwrap().to_string());
    cmd.args(args.map(|v| v.to_string()));
    cmd.
}
*/
