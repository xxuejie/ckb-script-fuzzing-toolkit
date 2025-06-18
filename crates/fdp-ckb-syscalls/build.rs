fn main() {
    let mut build = cc::Build::new();
    build
        .file("c_src/syscalls/fuzzed_data_provider.cc")
        .cpp(true)
        .include("c_include")
        .include("c_src")
        .include("c_deps/ckb-c-stdlib")
        .compile("fdp-c");
}
