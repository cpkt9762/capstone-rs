# capstone-rs

[![Crates.io Badge](https://img.shields.io/crates/v/capstone.svg)](https://crates.io/crates/capstone)

> **Fork of [capstone-rust/capstone-rs](https://github.com/capstone-rust/capstone-rs) with added Solana sBPF disassembly support.**

---

## Solana sBPF Support

This fork extends the upstream capstone-rs bindings with support for **Solana sBPF** (Solana Berkeley Packet Filter), the custom bytecode format used by Solana on-chain programs.

### What is Solana sBPF?

Solana programs are compiled to sBPF, a custom variant of eBPF with Solana-specific instruction semantics (different calling conventions, register layout, and syscall ABI). This fork bundles a capstone C library patched with sBPF architecture support and exposes a full Rust API.

### Supported features

| Feature | Description |
|---|---|
| Registers | `r0`–`r10` (11 registers) |
| ALU instructions | `add32/64`, `sub32/64`, `mul32/64`, `div32/64`, `or`, `and`, `lsh`, `rsh`, `arsh`, `neg`, `mod`, `xor`, `mov` |
| Load/Store | `lddw`, `ldxb/h/w/dw`, `stb/h/w/dw`, `stxb/h/w/dw` |
| Byte-swap | `le16/32/64`, `be16/32/64` |
| Branches | `ja`, `jeq`, `jgt`, `jge`, `jset`, `jne`, `jsgt`, `jsge`, `jlt`, `jle`, `jslt`, `jsle` |
| Control flow | `call`, `exit` |
| Operand access info | signed/unsigned flag, read/write access type |

### Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
capstone = { git = "https://github.com/cpkt9762/capstone-rs", features = ["arch_sbpf"] }
```

### Usage example

```rust
use capstone::prelude::*;
use capstone::arch::sbpf;

// sBPF bytecode: mov64 r1, 1; ldxw r0, [r10-12]; exit
const SBPF_CODE: &[u8] = &[
    0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,  // mov64 r1, 1
    0x61, 0xa0, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00,  // ldxw  r0, [r10-12]
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // exit
];

fn main() {
    let cs = Capstone::new()
        .sbpf()
        .mode(sbpf::ArchMode::SbpfV0)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let insns = cs.disasm_all(SBPF_CODE, 0x100)
        .expect("Failed to disassemble");

    println!("Found {} instructions", insns.len());
    for insn in insns.as_ref() {
        println!("0x{:04x}: {} {}", insn.address(), insn.mnemonic().unwrap_or(""), insn.op_str().unwrap_or(""));
    }
}
```

Output:
```
Found 3 instructions
0x0100: mov64 r1, 1
0x0108: ldxw r0, [r10-0xc]
0x0110: exit
```

### Feature flags

| Flag | Description |
|---|---|
| `arch_sbpf` | Enable Solana sBPF disassembly support |
| `support_all_archs` | Enable all architectures including sBPF (default) |

---

## Original capstone-rs

Linux/macOS/Windows [![Github Workflow CI Badge](https://github.com/capstone-rust/capstone-rs/actions/workflows/main.yml/badge.svg)](https://github.com/capstone-rust/capstone-rs/actions)
|
FreeBSD [![Cirrus CI Badge](https://api.cirrus-ci.com/github/capstone-rust/capstone-rs.svg)](https://cirrus-ci.com/github/capstone-rust/capstone-rs)

Bindings to the [capstone library][upstream] disassembly framework.

The `Capstone` struct is the main interface to the library.

# Requirements

`capstone-rs` uses the [`capstone-sys`](capstone-sys) crate to provide the low-level bindings to the Capstone C library.

See the [`capstone-sys`](capstone-sys) page for the requirements and supported platforms.

* Minimum Rust Version: `1.81.0`

# Example

```rust
extern crate capstone;

use capstone::prelude::*;

const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\x14\x9e\x08\x00\x45\x31\xe4";

fn main() {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let insns = cs.disasm_all(X86_CODE, 0x1000)
        .expect("Failed to disassemble");
    println!("Found {} instructions", insns.len());
    for i in insns.as_ref() {
        println!();
        println!("{}", i);
        let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();
        println!("  operands: {}", ops.len());
    }
}
```

# Features

- `full`<sup>&dagger;</sup>: do not compile Capstone C library in
  [diet mode](https://www.capstone-engine.org/diet.html)
- `std`<sup>&dagger;</sup>: enable `std`-only features, such as the
  [`Error` trait](https://doc.rust-lang.org/std/error/trait.Error.html)
- `use_bindgen`: run `bindgen` to generate Rust bindings to Capstone C library
  instead of using pre-generated bindings (not recommended)
- `arch_$ARCH`<sup>&dagger;</sup>: enable arch `$ARCH` support in capstone,
  e.g. `arch_arm64` enables arch arm64 support
- `arch_sbpf`<sup>&dagger;</sup>: enable **Solana sBPF** support *(added in this fork)*
- `support_all_archs`<sup>&dagger;</sup>: enable all archs available
  in capstone, imply all `arch_$ARCH` features (includes `arch_sbpf`)
- `check_only`: do not compile and link capstone C library,
  you can enable it to speed up `cargo check` by 5x

<sup>&dagger;</sup>: enabled by default

# Upstream

This fork is based on [capstone-rust/capstone-rs](https://github.com/capstone-rust/capstone-rs).
Issues unrelated to Solana sBPF should be reported upstream.

# License

[MIT](capstone-rs/LICENSE)

[upstream]: https://www.capstone-engine.org/
