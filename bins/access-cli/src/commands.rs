//! One module per subcommand. Each exposes its `Args` (clap) and a `run` that returns an exit
//! code; nothing is shared between them but [`crate::config`] and [`crate::exit`].

pub(crate) mod migrate;
