// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use diem_types::access_path::AccessPath;

use std::cell::UnsafeCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

struct WritesPlaceholder {
    data: BTreeMap<WriteVersionKey, WriteVersionValue>,
}

impl WritesPlaceholder {
    pub fn new() -> WritesPlaceholder {
        WritesPlaceholder {
            data: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn add_placeholder(&mut self, key: AccessPath, version: u64) {
        let key = WriteVersionKey::new(key, version);
        let value = WriteVersionValue::new();
        self.data.insert(key, value);
    }

    pub fn write(&self, key: AccessPath, version: u64, data: Option<Vec<u8>>) -> Result<(), ()> {
        // By construction there will only be a single writer, before the
        // write there will be no readers on the variable.
        // So it is safe to go ahead and write without any further check.
        // Then update the flag to enable reads.

        let entry = self
            .data
            .get(&WriteVersionKey::new(key, version))
            .ok_or_else(|| ())?;

        unsafe {
            let val = &mut *entry.data.get();
            *val = data;
        }

        entry.flag.store(FLAG_DONE, Ordering::Release);
        Ok(())
    }

    pub fn skip(&self, key: AccessPath, version: u64) -> Result<(), ()> {
        let key = WriteVersionKey::new(key, version);
        let entry = self
            .data
            .get(&key)
            .ok_or_else(|| ())?;
        entry.flag.store(FLAG_SKIP, Ordering::Release);
        Ok(())
    }

    pub fn read(
        &self,
        key: AccessPath,
        version: u64,
    ) -> Result<Option<Vec<u8>>, Option<WriteVersionKey>> {

        // Get the smaller key
        use std::ops::Bound::Excluded;
        let key_end = WriteVersionKey::new(key.clone(), version);
        let key_zero = WriteVersionKey::new(key, 0_u64);
        let mut iter = self.data.range(key_zero..key_end);

        while let Some((entry_key, entry_val)) = iter.next_back() {
            if entry_key.version < version {

                let flag = entry_val.flag.load(Ordering::Acquire);

                // Return this key, must wait.
                if flag == FLAG_UNASSIGNED {
                    return Err(Some(entry_key.clone()))
                }

                if flag == FLAG_SKIP {
                    continue
                }

                if flag == FLAG_DONE {
                    let data_read_ref = unsafe { &*entry_val.data.get() };
                    return Ok(data_read_ref.clone())
                }

                unreachable!();
            }
        }

        Err(None)
    }
}

#[derive(Eq, Ord, PartialEq, PartialOrd, Clone, Debug)]
struct WriteVersionKey {
    path: AccessPath,
    version: u64,
}

impl WriteVersionKey {
    pub fn new(path: AccessPath, version: u64) -> WriteVersionKey {
        WriteVersionKey { path, version }
    }
}

const FLAG_UNASSIGNED: usize = 0;
const FLAG_DONE: usize = 2;
const FLAG_SKIP: usize = 3;

struct WriteVersionValue {
    flag: AtomicUsize,
    data: UnsafeCell<Option<Vec<u8>>>,
    _pad: [u8; 128], // Keep the flags on separate cache lines
                     // See Intel x64 multicore perf manual (Section 8).
}

impl WriteVersionValue {
    pub fn new() -> WriteVersionValue {
        WriteVersionValue {
            flag: AtomicUsize::new(FLAG_UNASSIGNED),
            data: UnsafeCell::new(None),
            _pad: [0; 128],
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use diem_types::{access_path::AccessPath, account_address::AccountAddress};

    #[test]
    fn create_write_read_placeholder_struct() {
        let ap1 = AccessPath {
            address: AccountAddress::new([1u8; AccountAddress::LENGTH]),
            path: b"/foo/b".to_vec(),
        };
        let ap2 = AccessPath {
            address: AccountAddress::new([2u8; AccountAddress::LENGTH]),
            path: b"/foo/c".to_vec(),
        };

        let mut placeholder = WritesPlaceholder::new();

        // Check structure creation
        placeholder.add_placeholder(ap1.clone(), 10);
        placeholder.add_placeholder(ap2.clone(), 10);
        placeholder.add_placeholder(ap2.clone(), 20);

        assert_eq!(3, placeholder.len());

        // Reads that should go the the DB return Err(None)
        let r1 = placeholder.read(ap1.clone(), 5);
        assert_eq!(Err(None), r1);

        // Reads at a version return the previous versions, not this
        // version.
        let r1 = placeholder.read(ap1.clone(), 10);
        assert_eq!(Err(None), r1);

        // Check reads into non-ready structs return the Err(entry)

        // Reads at a higher version return the previous version
        let r1 = placeholder.read(ap1.clone(), 15);
        assert_eq!(Err(Some(WriteVersionKey::new(ap1.clone(), 10))), r1);

        // Writes populate the entry
        let w1 = placeholder.write(ap1.clone(), 10, Some(vec![0, 0, 0]) );

        // Subsequent higher reads read this entry
        let r1 = placeholder.read(ap1.clone(), 15);
        assert_eq!(Ok(Some(vec![0, 0, 0])), r1);

        // Set skip works
        let w1 = placeholder.skip(ap1.clone(), 20);

        // Higher reads skip this entry
        let r1 = placeholder.read(ap1.clone(), 25);
        assert_eq!(Ok(Some(vec![0, 0, 0])), r1);

    }

}
