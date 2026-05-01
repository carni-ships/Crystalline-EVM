// Build script for orion-sys
// Links against the Orion static library and sets up include paths

fn main() {
    // Link against Orion library (contains real ANE implementations)
    println!("cargo:rustc-link-lib=static=orion");

    // Point to the Orion library location
    println!("cargo:rustc-link-search=/Users/carnation/Documents/Claude/zkANE/Orion");

    // Set up include paths for header files from Orion core
    println!("cargo:include=/Users/carnation/Documents/Claude/zkANE/Orion/core");

    // macOS-specific framework links for ANE/GPU
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=IOSurface");
    println!("cargo:rustc-link-lib=framework=Metal");
    println!("cargo:rustc-link-lib=framework=Accelerate");
    println!("cargo:rustc-link-lib=dylib=dl");
}
