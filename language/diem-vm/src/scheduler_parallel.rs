// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0


use diem_types::{
    access_path::AccessPath,
    transaction::{
        TransactionOutput,
    },
    vm_status::{VMStatus, },
};


use std::cell::UnsafeCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

unsafe impl Send for WritesPlaceholder {}
unsafe impl Sync for WritesPlaceholder {}


/// A structure that holds placeholders for each write to the database
//
//  The structure is created by one thread creating the scheduling, and
//  at that point it is used as a &mut by that single thread.
//
//  Then it is passed to all threads executing as a shared reference. At
//  this point only a single thread must write to any entry, and others
//  can read from it. Only entries are mutated using interior mutability,
//  but no entries can be added or deleted.
//
pub(crate) struct WritesPlaceholder {
    data: BTreeMap<WriteVersionKey, WriteVersionValue>,
    results : Vec<UnsafeCell<Option<(VMStatus, TransactionOutput)>>>,
}

impl WritesPlaceholder {
    pub fn new(len : usize) -> WritesPlaceholder {
        WritesPlaceholder {
            data: BTreeMap::new(),
            results : (0..len).map(|_| UnsafeCell::new(None)).collect(),
        }
    }

    pub fn set_result(&self, idx:usize, res: (VMStatus, TransactionOutput)) {
        // Only one thread can write at the time, so just set it.
        let entry = &self.results[idx];
        unsafe {
            let mut_entry = &mut*entry.get();
            *mut_entry = Some(res);
        }
    }

    pub fn get_all_results(self) -> Result<Vec<(VMStatus, TransactionOutput)>, VMStatus>{

        let results = self.results;
        Ok(results.into_iter().map(|entry| {
            let val = unsafe { &mut *entry.get() };
            let val = val.take();
            val.expect("ERROR: WE EXPECT ALL ENTRIES TO BE POPULATED WITH A RESULT!");
        }).collect())
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn add_placeholder(&mut self, key: AccessPath, version: usize) {
        let key = WriteVersionKey::new(key, version);
        let value = WriteVersionValue::new();
        self.data.insert(key, value);
    }

    pub fn write(&self, key: AccessPath, version: usize, data: Option<Vec<u8>>) -> Result<(), ()> {
        // By construction there will only be a single writer, before the
        // write there will be no readers on the variable.
        // So it is safe to go ahead and write without any further check.
        // Then update the flag to enable reads.

        let entry = self
            .data
            .get(&WriteVersionKey::new(key, version))
            .ok_or_else(|| ())?;

        #[cfg(test)]
        {
            // Test the invariant holds
            let flag = entry.flag.load(Ordering::Acquire);
            if flag != FLAG_UNASSIGNED {
                panic!("Cannot write twice to same entry.");
            }

        }

        unsafe {
            let val = &mut *entry.data.get();
            *val = data;
        }

        entry.flag.store(FLAG_DONE, Ordering::Release);
        Ok(())
    }


    pub fn skip_if_not_set(&self, key: AccessPath, version: usize) -> Result<(), ()> {
        // We only write or skip once per entry
        // So it is safe to go ahead and just do it.
        let key = WriteVersionKey::new(key, version);
        let entry = self
            .data
            .get(&key)
            .ok_or_else(|| ())?;

        // Test the invariant holds
        let flag = entry.flag.load(Ordering::Acquire);
        if flag == FLAG_UNASSIGNED {
            entry.flag.store(FLAG_SKIP, Ordering::Release);
        }

        Ok(())
    }


    pub fn skip(&self, key: AccessPath, version: usize) -> Result<(), ()> {
        // We only write or skip once per entry
        // So it is safe to go ahead and just do it.
        let key = WriteVersionKey::new(key, version);
        let entry = self
            .data
            .get(&key)
            .ok_or_else(|| ())?;

        #[cfg(test)]
        {
            // Test the invariant holds
            let flag = entry.flag.load(Ordering::Acquire);
            if flag != FLAG_UNASSIGNED {
                panic!("Cannot write twice to same entry.");
            }
        }


        entry.flag.store(FLAG_SKIP, Ordering::Release);
        Ok(())
    }

    pub fn read(
        &self,
        key: AccessPath,
        version: usize,
    ) -> Result<Option<Vec<u8>>, Option<WriteVersionKey>> {

        // Get the smaller key
        use std::ops::Bound::Excluded;
        let key_end = WriteVersionKey::new(key.clone(), version);
        let key_zero = WriteVersionKey::new(key, 0_usize);
        let mut iter = self.data.range(key_zero..key_end);

        while let Some((entry_key, entry_val)) = iter.next_back() {
            if entry_key.version < version {

                let flag = entry_val.flag.load(Ordering::Acquire);

                // Return this key, must wait.
                if flag == FLAG_UNASSIGNED {
                    return Err(Some(entry_key.clone()))
                }

                // If we are to skip this entry, pick the next one
                if flag == FLAG_SKIP {
                    continue
                }

                // The entry is populated so return its contents
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
pub(crate) struct WriteVersionKey {
    path: AccessPath,
    version: usize,
}

impl WriteVersionKey {
    pub fn new(path: AccessPath, version: usize) -> WriteVersionKey {
        WriteVersionKey { path, version }
    }
}

const FLAG_UNASSIGNED: usize = 0;
const FLAG_DONE: usize = 2;
const FLAG_SKIP: usize = 3;

pub(crate) struct WriteVersionValue {
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

use diem_state_view::{StateView, StateViewId};
use std::{thread, time};

const ONE_MILLISEC : std::time::Duration = time::Duration::from_millis(10);

pub(crate) struct VersionedStateView<'view> {
    version : usize,
    base_view : &'view dyn StateView,
    placeholder : &'view WritesPlaceholder,
}

impl<'view> VersionedStateView<'view>{
    pub fn new(version : usize, base_view: &'view StateView, placeholder : &'view WritesPlaceholder) -> VersionedStateView<'view> {
        VersionedStateView {
            version,
            base_view,
            placeholder,
        }
    }

    pub fn will_read_block(&self, access_path: &AccessPath) -> bool {
        let read = self.placeholder.read(access_path.clone(), self.version);
        if let Err(Some(_)) = read {
            return true;
        }
        return false;

    }
}

impl<'block> StateView for VersionedStateView<'block> {
    // Get some data either through the cache or the `StateView` on a cache miss.
    fn get(&self, access_path: &AccessPath) -> anyhow::Result<Option<Vec<u8>>> {

        let mut loop_iterations = 0;
        loop {

            let read = self.placeholder.read(access_path.clone(), self.version);

            // Go to the Database
            if let Err(None) = read{
                return self.base_view.get(access_path);
            }

            // Read is a success
            if let Ok(data) = read {
                /*
                if loop_iterations != 0 {
                    println!("BLOCK ON {} ver={} iter={}", access_path, self.version, loop_iterations);
                }
                */
                return Ok(data);
            }

            loop_iterations+= 1;
            if loop_iterations < 500 {
                ::std::sync::atomic::spin_loop_hint();
            }
            else
            {
                thread::sleep(ONE_MILLISEC);

                /*
                if loop_iterations % 10 == 0 {
                    if let Err(Some(key)) = read {
                        println!("Wait on: {:?}", key);
                    }

                    println!("BIG BLOCK ON {} ver={} iter={}", access_path, self.version, loop_iterations);
                }
                */
            }
        }


    }

    fn multi_get(&self, _access_paths: &[AccessPath]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        unimplemented!()
    }

    fn is_genesis(&self) -> bool {
        self.base_view.is_genesis()
    }

    fn id(&self) -> StateViewId {
        self.base_view.id()
    }
}
