# Adding a provider

A provider adapts one crypto library to the internal vtable in
[`src/internal/provider.h`](../src/internal/provider.h). The core has
already validated every argument, so a provider only translates calls.

## Steps

1. **Create `src/providers/<name>.c`** exporting
   `const sdc_provider sdc_provider_<name>`. Fill in `name`, `supports`
   and the operations you implement; leave the rest `NULL`.
2. **`supports(alg)`** must return non-zero only for algorithms whose
   operations you implement. Partial support is fine: the core picks a
   provider per operation and falls through to the next one.
3. **Honour the canonical encodings** listed in [API.md](API.md#encodings).
   Convert to and from the library's native formats inside the provider.
4. **Return the right status**: `SDC_ERR_AUTH_FAILED` for an AEAD tag
   mismatch, `SDC_ERR_VERIFY_FAILED` for a bad signature,
   `SDC_ERR_INVALID_ARG` for an unusable key, `SDC_ERR_PROVIDER` for
   anything the library reports as an internal error.
5. **Declare it** in `provider.h` and **register it** in the `g_all` list in
   `src/core/registry.c`, both under `#ifdef SDC_HAVE_<NAME>`. The list
   order is the default preference order.
6. **Add a CMake block** with an `SDC_WITH_<NAME>` option that adds the
   source, defines `SDC_HAVE_<NAME>` and appends to `SDC_LINK_LIBS` and
   `SDC_PROVIDERS`.

## Testing

No new tests are needed to get coverage:

* `test_kat` runs every known-answer vector against each provider that can
  serve it.
* `test_interop` checks every pair of providers sharing an algorithm,
  including keys and signatures made by one and consumed by the other.
* `example_<name>` runs the demo with `SDC_PROVIDER=<name>`.

Also build with only your provider enabled
(`-DSDC_WITH_OPENSSL=OFF ...`) and with `-DSDC_SANITIZE=ON`.
