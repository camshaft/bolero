use structopt::StructOpt;

#[derive(Clone, Copy, Debug, StructOpt)]
pub struct Args {
    /// 0: none, 1: entry block, 2: all blocks, 3: all blocks and critical edges
    #[structopt(long, default_value = "3")]
    pub sanitizer_coverage_level: u8,

    /// increments 8-bit counter for every edge
    #[structopt(long)]
    pub sanitizer_coverage_inline_8bit_counters: Option<Option<bool>>,

    /// sets a boolean flag for every edge
    #[structopt(long)]
    pub sanitizer_coverage_inline_bool_flag: Option<Option<bool>>,

    /// create a static PC table
    #[structopt(long)]
    pub sanitizer_coverage_pc_table: Option<Option<bool>>,

    /// Reduce the number of instrumented blocks
    #[structopt(long)]
    pub sanitizer_coverage_prune_blocks: Option<Option<bool>>,

    /// max stack depth tracing
    #[structopt(long)]
    pub sanitizer_coverage_stack_depth: Option<Option<bool>>,

    /// Tracing of CMP and similar instructions
    #[structopt(long)]
    pub sanitizer_coverage_trace_compares: Option<Option<bool>>,

    /// Tracing of DIV instructions
    #[structopt(long)]
    pub sanitizer_coverage_trace_divs: Option<Option<bool>>,

    /// Tracing of GEP instructions
    #[structopt(long)]
    pub sanitizer_coverage_trace_geps: Option<Option<bool>>,

    /// Experimental pc tracing
    #[structopt(long)]
    pub sanitizer_coverage_trace_pc: Option<Option<bool>>,

    /// pc tracing with a guard
    #[structopt(long)]
    pub sanitizer_coverage_trace_pc_guard: Option<Option<bool>>,
}

#[derive(Clone, Copy, Debug)]
pub struct Flags {
    pub sanitizer_coverage_inline_8bit_counters: bool,
    pub sanitizer_coverage_inline_bool_flag: bool,
    pub sanitizer_coverage_level: u8,
    pub sanitizer_coverage_pc_table: bool,
    pub sanitizer_coverage_prune_blocks: bool,
    pub sanitizer_coverage_stack_depth: bool,
    pub sanitizer_coverage_trace_compares: bool,
    pub sanitizer_coverage_trace_divs: bool,
    pub sanitizer_coverage_trace_geps: bool,
    pub sanitizer_coverage_trace_pc: bool,
    pub sanitizer_coverage_trace_pc_guard: bool,
}

impl Flags {
    pub const fn default() -> Self {
        Self {
            sanitizer_coverage_inline_8bit_counters: false,
            sanitizer_coverage_inline_bool_flag: false,
            sanitizer_coverage_level: 3,
            sanitizer_coverage_pc_table: false,
            sanitizer_coverage_prune_blocks: false,
            sanitizer_coverage_stack_depth: false,
            sanitizer_coverage_trace_compares: false,
            sanitizer_coverage_trace_divs: false,
            sanitizer_coverage_trace_geps: false,
            sanitizer_coverage_trace_pc: false,
            sanitizer_coverage_trace_pc_guard: false,
        }
    }

    pub fn with_args(&mut self, args: &Args) {
        macro_rules! flag {
            ($field:ident) => {
                match args.$field {
                    Some(Some(value)) => {
                        self.$field = value;
                    }
                    Some(None) => {
                        self.$field = true;
                    }
                    None => {
                        // use the defaults
                    }
                }
            };
        }

        flag!(sanitizer_coverage_inline_8bit_counters);
        flag!(sanitizer_coverage_inline_bool_flag);
        self.sanitizer_coverage_level = args.sanitizer_coverage_level;
        flag!(sanitizer_coverage_pc_table);
        flag!(sanitizer_coverage_prune_blocks);
        flag!(sanitizer_coverage_stack_depth);
        flag!(sanitizer_coverage_trace_compares);
        flag!(sanitizer_coverage_trace_divs);
        flag!(sanitizer_coverage_trace_geps);
        flag!(sanitizer_coverage_trace_pc);
        flag!(sanitizer_coverage_trace_pc_guard);
    }
}

impl IntoIterator for Flags {
    type IntoIter = std::vec::IntoIter<Self::Item>;
    type Item = String;

    fn into_iter(self) -> Self::IntoIter {
        let mut flags = vec![];

        macro_rules! flag {
            ($field:ident) => {{
                let mut value = "-Cllvm-args=-".to_string();
                value += &stringify!().replace('-', "_");
                value.push('=');
                if self.$field {
                    value.push('1')
                } else {
                    value.push('0')
                }
                value
            }};
        }

        flag!(sanitizer_coverage_inline_8bit_counters);
        flag!(sanitizer_coverage_inline_bool_flag);
        match self.sanitizer_coverage_level {
            0 => {}
            1 => {}
            2 => {}
            _ => {}
        }
        flag!(sanitizer_coverage_pc_table);
        flag!(sanitizer_coverage_prune_blocks);
        flag!(sanitizer_coverage_stack_depth);
        flag!(sanitizer_coverage_trace_compares);
        flag!(sanitizer_coverage_trace_divs);
        flag!(sanitizer_coverage_trace_geps);
        flag!(sanitizer_coverage_trace_pc);
        flag!(sanitizer_coverage_trace_pc_guard);

        flags.into_iter()
    }
}
