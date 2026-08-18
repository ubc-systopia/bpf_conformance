# Alivio verifier plugin

This standalone adapter lets `bpf_conformance_runner` use an unmodified
Alivio executable as a verifier plugin. The runner supplies an ELF XDP
program; the adapter writes it to a temporary file and invokes Alivio's
existing `verify` command.

Verifier plugin exit codes are:

- `0`: accepted
- `1`: rejected; stdout contains the verifier reason
- `2` or greater: adapter or infrastructure error

Example:

```sh
build/bin/bpf_conformance_runner \
  --test_file_directory tests \
  --plugin_path build/bin/alivio_plugin \
  --plugin_options "--alivio /path/to/alivio" \
  --verifier true \
  --xdp_prolog true \
  --elf true
```

Existing tests default to expected verifier acceptance. A verifier-negative
test can declare its expectation and an optional ECMAScript regular expression
that is searched for in the complete verifier output:

```text
-- verifier
reject
-- verifier reason
Unsafe (bpf_context|ctx) access
```
