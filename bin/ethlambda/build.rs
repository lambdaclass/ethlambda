use vergen::{Emitter, RustcBuilder};
use vergen_git2::Git2Builder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let git2 = Git2Builder::default().branch(true).sha(true).build()?;
    let rustc = RustcBuilder::default()
        .semver(true)
        .host_triple(true)
        .build()?;

    Emitter::default()
        .add_instructions(&rustc)?
        .add_instructions(&git2)?
        .emit()?;

    Ok(())
}
