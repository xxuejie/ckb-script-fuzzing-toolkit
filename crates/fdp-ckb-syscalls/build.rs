fn main() {
    let mut build = cc::Build::new();
    build
        .file("c_src/syscalls/fuzzed_data_provider.cc")
        .cpp(true)
        .include("c_include")
        .include("c_src")
        .include("c_deps/ckb-c-stdlib");
    if cfg!(feature = "print-debug-messages") {
        build.define("CKB_FUZZING_PRINT_DEBUG_MESSAGE", None);
    }
    build.compile("fdp-c");
}
