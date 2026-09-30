use keyring::{Entry, Error};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Only this uniquely named synthetic entry is addressed. No enumeration,
    // real DBX service/user names, real profile, or actual secret is consulted.
    let user = format!("fixture-{}-{}", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
    let entry = match Entry::new("org.dbx.ci.synthetic-keyring", &user) {
        Ok(entry) => entry,
        Err(_) => { println!("{{\"status\":\"unavailable\",\"stage\":\"create_handle\",\"real_profiles_accessed\":false}}"); return; }
    };
    if !matches!(entry.get_password(), Err(Error::NoEntry)) {
        println!("{{\"status\":\"unavailable\",\"stage\":\"fresh_entry_check\",\"real_profiles_accessed\":false}}"); return;
    }
    if entry.set_password("synthetic-ci-only-no-real-account").is_err() {
        println!("{{\"status\":\"unavailable\",\"stage\":\"fixture_write\",\"real_profiles_accessed\":false}}"); return;
    }
    struct Cleanup<'a>(&'a Entry);
    impl Drop for Cleanup<'_> { fn drop(&mut self) { let _ = self.0.delete_credential(); } }
    let _cleanup = Cleanup(&entry);
    let roundtrip = entry.get_password().is_ok_and(|v| v == "synthetic-ci-only-no-real-account");
    let deleted = entry.delete_credential().is_ok();
    let absent = matches!(entry.get_password(), Err(Error::NoEntry));
    println!("{{\"status\":\"{}\",\"native_backend\":\"Windows Credential Manager via keyring3.6.3/windows-native\",\"synthetic_roundtrip\":{},\"fixture_deleted\":{},\"fixture_absence_verified\":{},\"real_profiles_accessed\":false}}", if roundtrip && deleted && absent { "passed" } else { "failed" }, roundtrip, deleted, absent);
    if !(roundtrip && deleted && absent) { std::process::exit(1); }
}
