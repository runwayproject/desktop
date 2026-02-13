fn main() {
    cxx_build::bridge("src/lib.rs")
        .compile("mlsffi");

    println!("cargo:rerun-if-changed=src/lib.rs");
}