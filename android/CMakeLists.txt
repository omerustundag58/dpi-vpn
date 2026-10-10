# Rust dpi-core .so dosyasini Android'e baglayan CMake iskeleti (derleme cargo-ndk ile yapilir).
cmake_minimum_required(VERSION 3.22.1)
project(dpi_vpn_jni)
# Rust tarafi cargo-ndk ile derlenir: cargo ndk -t arm64-v8a -o ../jniLibs build -p dpi-core
# Burada sadece JNI shim (ileride) ve log baglantisi tanimlanir; .so onceden hazir beklenir.
add_library(dpi_jni_shim STATIC stub.c) # stub.c yoksa bu satiri kaldirin, dogrudan jniLibs kullanin
find_library(log-lib log)
target_link_libraries(dpi_jni_shim ${log-lib})
set_target_properties(dpi_jni_shim PROPERTIES LINKER_LANGUAGE C)
