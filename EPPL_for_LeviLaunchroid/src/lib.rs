#![feature(once_cell_try)]
mod epplll;

#[ctor::ctor]
fn safe_setup() {
    std::panic::set_hook(Box::new(move |_panic_info| {}));
    main();
}

fn main() {
    let _ = epplll::patch_piston_limits();
}