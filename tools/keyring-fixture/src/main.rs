//! Check only a uniquely named synthetic Credential Manager entry on Windows.
//! No DBX profile, production key name, or credential enumeration is involved.

use std::process::ExitCode;

#[cfg(any(windows, test))]
const SYNTHETIC_PASSWORD: &str = "synthetic-ci-only-no-real-account";

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq)]
enum Read {
    Missing,
    Value(String),
}

#[cfg(any(windows, test))]
trait Credential {
    fn read(&self) -> Result<Read, ()>;
    fn write(&self, value: &str) -> Result<(), ()>;
    fn delete(&self) -> Result<(), ()>;
}

#[cfg(any(windows, test))]
struct Cleanup<'a, T: Credential>(&'a T);

#[cfg(any(windows, test))]
impl<T: Credential> Drop for Cleanup<'_, T> {
    fn drop(&mut self) {
        // Best effort retry on error/panic. Explicit deletion and absence checks
        // below are still required to report success.
        let _ = self.0.delete();
    }
}

#[cfg(any(windows, test))]
fn check_entry(entry: &impl Credential) -> Result<(), &'static str> {
    match entry.read() {
        Ok(Read::Missing) => {}
        // Never overwrite or delete even an unexpectedly existing fixture name.
        Ok(Read::Value(_)) => return Err("fixture_name_already_exists"),
        Err(()) => return Err("fresh_entry_check"),
    }
    // Arm cleanup before a write: a failed native write may have partially
    // succeeded. Returning an error unwinds this guard before main exits.
    let cleanup = Cleanup(entry);
    entry.write(SYNTHETIC_PASSWORD).map_err(|()| "fixture_write")?;
    match entry.read() {
        Ok(Read::Value(value)) if value == SYNTHETIC_PASSWORD => {}
        _ => return Err("fixture_roundtrip"),
    }
    entry.delete().map_err(|()| "fixture_delete")?;
    match entry.read() {
        Ok(Read::Missing) => {}
        _ => return Err("fixture_absence_check"),
    }
    // The guard is harmless after explicit deletion (NoEntry). Retain it even
    // if reporting success fails, so every post-write path attempts cleanup.
    drop(cleanup);
    Ok(())
}

#[cfg(windows)]
impl Credential for keyring::Entry {
    fn read(&self) -> Result<Read, ()> {
        match self.get_password() {
            Ok(value) => Ok(Read::Value(value)),
            Err(keyring::Error::NoEntry) => Ok(Read::Missing),
            Err(_) => Err(()),
        }
    }

    fn write(&self, value: &str) -> Result<(), ()> {
        self.set_password(value).map_err(|_| ())
    }

    fn delete(&self) -> Result<(), ()> {
        self.delete_credential().map_err(|_| ())
    }
}

#[cfg(windows)]
fn native_check() -> Result<(), &'static str> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "fixture_clock")?.as_nanos();
    let user = format!("fixture-{}-{timestamp}", std::process::id());
    let entry = keyring::Entry::new("org.dbx.ci.synthetic-keyring", &user).map_err(|_| "create_handle")?;
    check_entry(&entry)
}

fn main() -> ExitCode {
    #[cfg(windows)]
    match native_check() {
        Ok(()) => {
            println!(concat!(
                "{{\"status\":\"passed\",\"native_backend\":\"Windows Credential Manager\",",
                "\"synthetic_roundtrip\":true,\"fixture_deleted\":true,",
                "\"fixture_absence_verified\":true,\"real_profiles_accessed\":false}}"
            ));
            ExitCode::SUCCESS
        }
        Err(stage) => {
            // Unavailable backends do not produce a green native verification.
            // Never print backend errors, usernames, or credential values.
            println!("{{\"status\":\"failed\",\"stage\":\"{stage}\",\"real_profiles_accessed\":false}}");
            ExitCode::FAILURE
        }
    }
    #[cfg(not(windows))]
    {
        println!("{{\"status\":\"unsupported\",\"reason\":\"requires_windows\",\"real_profiles_accessed\":false}}");
        ExitCode::from(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Fake {
        reads: RefCell<VecDeque<Result<Read, ()>>>,
        writes: RefCell<Vec<String>>,
        deletes: RefCell<usize>,
        fail_write: bool,
        fail_delete: bool,
    }

    impl Credential for Fake {
        fn read(&self) -> Result<Read, ()> {
            self.reads.borrow_mut().pop_front().expect("unexpected read")
        }
        fn write(&self, value: &str) -> Result<(), ()> {
            self.writes.borrow_mut().push(value.to_owned());
            if self.fail_write {
                Err(())
            } else {
                Ok(())
            }
        }
        fn delete(&self) -> Result<(), ()> {
            *self.deletes.borrow_mut() += 1;
            if self.fail_delete {
                Err(())
            } else {
                Ok(())
            }
        }
    }

    fn fixture(reads: Vec<Result<Read, ()>>) -> Fake {
        Fake { reads: RefCell::new(reads.into()), ..Fake::default() }
    }

    #[test]
    fn roundtrip_deletes_and_verifies_absence() {
        let entry = fixture(vec![Ok(Read::Missing), Ok(Read::Value(SYNTHETIC_PASSWORD.into())), Ok(Read::Missing)]);
        assert_eq!(check_entry(&entry), Ok(()));
        assert_eq!(*entry.writes.borrow(), [SYNTHETIC_PASSWORD]);
        assert_eq!(*entry.deletes.borrow(), 2);
    }

    #[test]
    fn existing_name_is_never_modified() {
        let entry = fixture(vec![Ok(Read::Value("preexisting".into()))]);
        assert_eq!(check_entry(&entry), Err("fixture_name_already_exists"));
        assert!(entry.writes.borrow().is_empty());
        assert_eq!(*entry.deletes.borrow(), 0);
    }

    #[test]
    fn unavailable_backend_fails_without_modification() {
        let entry = fixture(vec![Err(())]);
        assert_eq!(check_entry(&entry), Err("fresh_entry_check"));
        assert!(entry.writes.borrow().is_empty());
        assert_eq!(*entry.deletes.borrow(), 0);
    }

    #[test]
    fn possibly_partial_write_still_attempts_cleanup() {
        let mut entry = fixture(vec![Ok(Read::Missing)]);
        entry.fail_write = true;
        assert_eq!(check_entry(&entry), Err("fixture_write"));
        assert_eq!(*entry.deletes.borrow(), 1);
    }

    #[test]
    fn wrong_missing_or_unreadable_roundtrip_cleans_up() {
        for read in [Ok(Read::Value("wrong".into())), Ok(Read::Missing), Err(())] {
            let entry = fixture(vec![Ok(Read::Missing), read]);
            assert_eq!(check_entry(&entry), Err("fixture_roundtrip"));
            assert_eq!(*entry.deletes.borrow(), 1);
        }
    }

    #[test]
    fn failed_deletion_is_retried_and_never_reported_as_success() {
        let mut entry = fixture(vec![Ok(Read::Missing), Ok(Read::Value(SYNTHETIC_PASSWORD.into()))]);
        entry.fail_delete = true;
        assert_eq!(check_entry(&entry), Err("fixture_delete"));
        assert_eq!(*entry.deletes.borrow(), 2);
    }

    #[test]
    fn retained_or_unreadable_entry_fails_absence_check_and_cleans_up() {
        for read in [Ok(Read::Value("retained".into())), Err(())] {
            let entry = fixture(vec![Ok(Read::Missing), Ok(Read::Value(SYNTHETIC_PASSWORD.into())), read]);
            assert_eq!(check_entry(&entry), Err("fixture_absence_check"));
            assert_eq!(*entry.deletes.borrow(), 2);
        }
    }
}
