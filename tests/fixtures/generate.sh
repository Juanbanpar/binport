#!/usr/bin/env bash
# Build fixtures as data, never execute them. Optional argument: output directory.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
src="$root/tests/fixtures/src"
out=${1:-"$root/tests/fixtures"}
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd)
tmp=$(mktemp -d -t binport-fixtures-XXXXXXXX)
trap 'rm -r -- "$tmp"' EXIT
cd -- "$out"
flags=(-Wl,--build-id=none -fno-ident)
for name in pie non-pie shared-library static-glibc static-pie; do
    case "$name" in
        pie) options=(-fPIE -pie);;
        non-pie) options=(-fno-pie -no-pie);;
        shared-library) options=(-shared -fPIC -Wl,-soname,libtiny.so.1);;
        static-glibc) options=(-static -s);;
        static-pie) options=(-static-pie -s);;
    esac
    cc "${flags[@]}" "${options[@]}" "$src/tiny.c" -o "$out/$name"
done
musl-gcc "${flags[@]}" "$src/tiny.c" -o "$out/musl-dynamic"
musl-gcc "${flags[@]}" -static "$src/tiny.c" -o "$out/musl-static"
cc -c "$src/tiny.c" -o "$out/relocatable"
cc "${flags[@]}" -m32 -nostdlib -static "$src/start.c" -o "$out/elf32"
clang --target=aarch64_be-linux-gnu -c "$src/start.c" -o "$out/aarch64-big-endian"

for arch in x86_64 i386 aarch64; do
    version_map="$src/provider.map"
    case "$arch" in
        x86_64) compiler=(cc); loader=/lib64/ld-linux-x86-64.so.2;;
        i386) compiler=(cc -m32); loader=/lib/ld-linux.so.2;;
        aarch64) compiler=(clang --target=aarch64-linux-gnu -fuse-ld=lld)
            loader=/lib/ld-linux-aarch64.so.1; version_map="$src/provider-aarch64.map";;
    esac
    lib="$tmp/$arch-libc.so"
    ns="$tmp/$arch-namespaces.so"
    "${compiler[@]}" "${flags[@]}" -nostdlib -shared -fPIC -fno-builtin "$src/provider.c" \
        "-Wl,--version-script=$version_map" -Wl,-soname,libc.so.6 -o "$lib"
    if [[ "$arch" == x86_64 ]]; then cp -- "$lib" "$out/versioned-provider"; fi
    "${compiler[@]}" "${flags[@]}" -nostdlib -shared -fPIC "$src/namespaces.c" \
        "-Wl,--version-script=$src/namespaces.map" -Wl,-soname,libnamespaces.so.1 -o "$ns"
    for name in glibc-old glibc-new namespaces runpath rpath; do
        if [[ "$arch" != x86_64 && "$name" != glibc-new ]]; then continue; fi
        output="$name"
        if [[ "$arch" != x86_64 ]]; then output="$arch-glibc-new"; fi
        extra_libs=()
        case "$name" in
            glibc-old) options=();;
            glibc-new) options=(-DNEW_GLIBC);;
            namespaces) options=(-DNAMESPACES); extra_libs=("$ns");;
            runpath) options=('-Wl,-rpath,$ORIGIN/lib::/opt/lib' -Wl,--enable-new-dtags);;
            rpath) options=('-Wl,-rpath,$ORIGIN/old' -Wl,--disable-new-dtags);;
        esac
        "${compiler[@]}" "${flags[@]}" -nostdlib -fno-builtin -fPIE -pie "$src/imports.c" \
            "${options[@]}" "$lib" "${extra_libs[@]}" "-Wl,--dynamic-linker=$loader" -o "$out/$output"
    done
done

cc "${flags[@]}" -nostdlib -shared -fPIC "$src/copy-provider.c" \
    "-Wl,--version-script=$src/copy-provider.map" -Wl,-soname,libc.so.6 -o "$tmp/copy.so"
cc "${flags[@]}" -nostdlib -fno-pie -no-pie "$src/copy-import.c" "$tmp/copy.so" \
    -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 -o "$out/copy-relocation"
cc "${flags[@]}" -nostdlib -shared -fPIC -fno-builtin "$src/imports.c" \
    "$out/versioned-provider" -o "$out/glibc-old-shared"
cc "${flags[@]}" -nostdlib -shared -fPIC -fno-builtin "$src/imports.c" \
    "$out/versioned-provider" -Wl,--auxiliary,libfirst.so,--auxiliary,libsecond.so \
    -o "$out/repeated-auxiliary"
cc "${flags[@]}" -nostdlib -fPIE -pie "$src/weak-import.c" "$out/versioned-provider" \
    -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2 -o "$tmp/weak-import"

# GNU NEEDED properties without a system CRT's properties.
for name in x86-64-v2 x86-64-v3 x86-64-v4 isa-used-only isa-unknown-bits vendor-note; do
    kind=0xc0008002
    extra_sources=()
    case "$name" in
        x86-64-v2) mask=3;;
        x86-64-v3) mask=7;;
        x86-64-v4) mask=15;;
        isa-used-only) mask=7; kind=0xc0010002;;
        isa-unknown-bits) mask=17;;
        vendor-note) mask=7; extra_sources=("$src/vendor-note.s");;
    esac
    cat > "$tmp/note.s" <<EOF
.section .note.gnu.property,"a"
.p2align 3
.long 4, 16, 5
.asciz "GNU"
.long $kind, 4, $mask, 0
.text
.globl _start
_start: ret
.section .note.GNU-stack,"",@progbits
EOF
    cc "${flags[@]}" -nostdlib -static "$tmp/note.s" "${extra_sources[@]}" -o "$out/$name"
done
cargo run --quiet --locked --manifest-path "$root/Cargo.toml" --example fixture-tools -- mutate "$out" "$tmp/weak-import"
cargo run --quiet --locked --manifest-path "$root/Cargo.toml" --example fixture-tools -- manifest "$out"
