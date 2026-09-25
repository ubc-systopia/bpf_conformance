// bpf_conformance plugin for qmonnet/rbpf.
// Usage: rbpf_plugin [<hex memory>] [--jit|--interpret] [--no-verifier] [--no-r2-len]
// Program is read as hex bytes from stdin; r0 is printed in hex on success.
use std::io::Read;
use std::process::exit;

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    s.split_whitespace()
        .map(|t| u8::from_str_radix(t, 16).map_err(|e| format!("bad hex byte '{t}': {e}")))
        .collect()
}

// NOTE:
// bpf_conformance's original test suite was inherited from ubpf's test suite, which contains a
// test case that calls a ubpf specific helper function (call id 5, `call_unwind_fail`).
// However, the test case doesn't not actually rely on any behavior of the helper function.
// So we register a dummy helper call just to silence the testing failure.
fn helper_unwind(r1: u64, _: u64, _: u64, _: u64, _: u64) -> u64 { r1 }

fn no_verify(_: &[u8]) -> Result<(), std::io::Error> { Ok(()) }

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    exit(1)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut mem = Vec::new();
    if let Some(a) = args.first() {
        if !a.starts_with("--") {
            mem = decode_hex(a).unwrap_or_else(|e| die(e));
            args.remove(0);
        }
    }
    let (mut jit, mut verify, mut r2_len) = (false, true, true);
    for a in &args {
        match a.as_str() {
            "--jit" => jit = true,
            "--interpret" => jit = false,
            "--no-verifier" => verify = false,
            "--no-r2-len" => r2_len = false,
            "" => {}
            "--elf" => die("ELF input not supported"),
            _ => die(format!("unknown option {a}")),
        }
    }

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap_or_else(|e| die(e));
    let mut prog = decode_hex(&input).unwrap_or_else(|e| die(e));

    // rbpf only sets r1 = mem; the suite (like ubpf) expects r2 = mem length.
    // Prepending `mov r2, len` does not disturb PC-relative jumps/calls.
    if r2_len {
        let len = mem.len() as i32;
        let mut pre = vec![0xb7, 0x02, 0x00, 0x00];
        pre.extend_from_slice(&len.to_le_bytes());
        pre.extend_from_slice(&prog);
        prog = pre;
    }

    let mut vm = rbpf::EbpfVmRaw::new(None).unwrap_or_else(|e| die(e));
    if !verify {
        vm.set_verifier(no_verify).unwrap_or_else(|e| die(e));
    }
    vm.set_program(&prog).unwrap_or_else(|e| die(e));
    vm.register_helper(5, helper_unwind).unwrap_or_else(|e| die(e));

    let res = if jit {
        vm.jit_compile().unwrap_or_else(|e| die(e));
        unsafe { vm.execute_program_jit(&mut mem) }
    } else {
        vm.execute_program(&mut mem)
    };
    match res {
        Ok(r0) => println!("{r0:x}"),
        Err(e) => die(e),
    }
}
