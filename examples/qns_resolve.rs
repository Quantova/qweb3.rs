//! Namehash a .qtov name and (optionally) resolve it against a node.
//!
//! Run namehash only (no node needed):
//!     cargo run --example qns_resolve
//!
//! Expected output:
//!     namehash('jason.qtov') = 0x9e882d38b25139dd882010f6031ad3ecf6672d898d513a3704f7bf59a798a9f6
//!
//! To resolve against a live node, set QUANTOVA_RPC and a registry address and use
//! q.resolve_name(registry, name) (see the README).

use qweb3::qns::namehash_hex;

fn main() {
    let name = "jason.qtov";
    println!("namehash('{name}') = {}", namehash_hex(name));
}
