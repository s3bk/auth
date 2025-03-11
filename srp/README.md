This implementation is derived from the [SRP crate in RustCrypto](https://github.com/RustCrypto/PAKEs/tree/6cb7679c0cddaf11c0041c49043aad4802214a58/srp).

However the underlying bigint library has been switched to a fixed size, stack allocated variant, and every line has been changed since.

Currently only G4096 is implemented. The other groups could be added as well by introducing a generic.
