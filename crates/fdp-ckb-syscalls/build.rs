fn main() {
    println!("cargo:rerun-if-changed=fuzzing_syscalls_all_in_one.h");

    let mut build = cc::Build::new();
    build.file("c.cc").compile("fdp-c");
}
