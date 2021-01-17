// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0
//! Scratchpad for on chain values during the execution.

use crate::{counters::CRITICAL_ERRORS, create_access_path, logging::AdapterLogSchema};
#[allow(unused_imports)]
use anyhow::format_err;
use diem_logger::prelude::*;
use diem_state_view::{StateView, StateViewId};
use diem_types::{
    access_path::AccessPath,
    on_chain_config::ConfigStorage,
    vm_status::StatusCode,
    write_set::{WriteOp, WriteSet},
};
use fail::fail_point;
use move_core_types::{
    account_address::AccountAddress,
    language_storage::{ModuleId, StructTag},
};
use move_vm_runtime::data_cache::{RemoteCache, RefBytes};
use std::collections::btree_map::BTreeMap;
use vm::errors::*;

use std::collections::HashSet;
use std::sync::Mutex;

/// A local cache for a given a `StateView`. The cache is private to the Diem layer
/// but can be used as a one shot cache for systems that need a simple `RemoteCache`
/// implementation (e.g. tests or benchmarks).
///
/// The cache is responsible to track all changes to the `StateView` that are the result
/// of transaction execution. Those side effects are published at the end of a transaction
/// execution via `StateViewCache::push_write_set`.
///
/// `StateViewCache` is responsible to give an up to date view over the data store,
/// so that changes executed but not yet committed are visible to subsequent transactions.
///
/// If a system wishes to execute a block of transaction on a given view, a cache that keeps
/// track of incremental changes is vital to the consistency of the data store and the system.
pub struct StateViewCache<'a> {
    pub data_view: &'a dyn StateView,
    data_map: BTreeMap<AccessPath, Option<Vec<u8>>>,
    reads: Mutex<Vec<AccessPath>>,
    record_reads: bool,
}

unsafe impl<'a> Sync for StateViewCache<'a> {}

impl<'a> StateViewCache<'a> {
    /// Create a `StateViewCache` give a `StateView`. Hold updates to the data store and
    /// forward data request to the `StateView` if not in the local cache.
    pub fn new(data_view: &'a dyn StateView) -> Self {
        StateViewCache {
            data_view,
            data_map: BTreeMap::new(),
            record_reads: false,
            reads: Mutex::new(Vec::new()),
        }
    }

    pub fn new_recorder(data_view: &'a dyn StateView) -> Self {
        StateViewCache {
            data_view,
            data_map: BTreeMap::new(),
            record_reads: true,
            reads: Mutex::new(Vec::new()),
        }
    }

    pub fn read_set(&self) -> Vec<AccessPath> {
        if !self.record_reads {
            panic!("NOT CONFIGURED TO RECORD READS");
        }
        self.reads.lock().unwrap().iter().cloned().collect()
    }

    // Publishes a `WriteSet` computed at the end of a transaction.
    // The effect is to build a layer in front of the `StateView` which keeps
    // track of the data as if the changes were applied immediately.
    pub(crate) fn push_write_set(&mut self, write_set: &WriteSet) {
        for (ref ap, ref write_op) in write_set.iter() {
            match write_op {
                WriteOp::Value(blob) => {
                    self.data_map.insert(ap.clone(), Some(blob.clone()));
                }
                WriteOp::Deletion => {
                    self.data_map.remove(ap);
                    self.data_map.insert(ap.clone(), None);
                }
            }
        }
    }


    // Publishes a `WriteSet` computed at the end of a transaction.
    // The effect is to build a layer in front of the `StateView` which keeps
    // track of the data as if the changes were applied immediately.
    pub(crate) fn push_changes(&mut self, changes : Vec<(AccessPath, Option<Vec<u8>>)>) {
        for (k, v) in changes {
            self.data_map.insert(k, v);
        }
    }

}

impl<'block> StateView for StateViewCache<'block> {
    // Get some data either through the cache or the `StateView` on a cache miss.
    fn get(&self, access_path: &AccessPath) -> anyhow::Result<Option<Vec<u8>>> {
        fail_point!("move_adapter::data_cache::get", |_| Err(format_err!(
            "Injected failure in data_cache::get"
        )));

        if self.record_reads {
            self.reads.lock().unwrap().push(access_path.clone());
        }

        match self.data_map.get(access_path) {
            Some(opt_data) => Ok(opt_data.clone()),
            None => match self.data_view.get(&access_path) {
                Ok(remote_data) => Ok(remote_data),
                // TODO: should we forward some error info?
                Err(e) => {
                    // create an AdapterLogSchema from the `data_view` in scope. This log_context
                    // does not carry proper information about the specific transaction and
                    // context, but this error is related to the given `StateView` rather
                    // than the transaction.
                    // Also this API does not make it easy to plug in a context
                    let log_context = AdapterLogSchema::new(self.data_view.id(), 0);
                    CRITICAL_ERRORS.inc();
                    error!(
                        log_context,
                        "[VM, StateView] Error getting data from storage for {:?}", access_path
                    );
                    Err(e)
                }
            },
        }
    }

    fn multi_get(&self, _access_paths: &[AccessPath]) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        unimplemented!()
    }

    fn is_genesis(&self) -> bool {
        self.data_view.is_genesis()
    }

    fn id(&self) -> StateViewId {
        self.data_view.id()
    }
}

impl<'block> RemoteCache for StateViewCache<'block> {
    fn get_module(&self, module_id: &ModuleId) -> VMResult<Option<Vec<u8>>> {
        RemoteStorage::new(self).get_module(module_id)
    }

    fn get_resource(
        &self,
        address: &AccountAddress,
        tag: &StructTag,
    ) -> PartialVMResult<Option<Vec<u8>>> {
        RemoteStorage::new(self).get_resource(address, tag)
    }
}

impl<'block> ConfigStorage for StateViewCache<'block> {
    fn fetch_config(&self, access_path: AccessPath) -> Option<Vec<u8>> {
        self.get(&access_path).ok()?
    }
}

// Adapter to convert a `StateView` into a `RemoteCache`.
pub struct RemoteStorage<'a, S>(&'a S);

impl<'a, S: StateView> RemoteStorage<'a, S> {
    pub fn new(state_store: &'a S) -> Self {
        Self(state_store)
    }

    pub fn get(&self, access_path: &AccessPath) -> PartialVMResult<Option<Vec<u8>>> {
        self.0
            .get(access_path)
            .map_err(|_| PartialVMError::new(StatusCode::STORAGE_ERROR))
    }
}

impl<'a, S: StateView> RemoteCache for RemoteStorage<'a, S> {
    fn get_module(&self, module_id: &ModuleId) -> VMResult<Option<Vec<u8>>> {
        // REVIEW: cache this?
        let ap = AccessPath::from(module_id);
        self.get(&ap).map_err(|e| e.finish(Location::Undefined))
    }

    fn get_resource(
        &self,
        address: &AccountAddress,
        struct_tag: &StructTag,
    ) -> PartialVMResult<Option<Vec<u8>>> {
        let ap = create_access_path(*address, struct_tag.clone());
        self.get(&ap)
    }
}

impl<'a, S: StateView> ConfigStorage for RemoteStorage<'a, S> {
    fn fetch_config(&self, access_path: AccessPath) -> Option<Vec<u8>> {
        self.get(&access_path).ok()?
    }
}
