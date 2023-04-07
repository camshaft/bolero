//! Module that provides functions convenient for different purposes.

/// Prints a styled warning message
#[cfg(target_os = "linux")]
pub(crate) fn warning(msg: &str) {
    let warning = console::style("warning").bold().yellow();
    let colon = console::style(":").bold();
    let msg_fmt = console::style(msg).bold();
    println!("{}{} {}", warning, colon, msg_fmt);
}
