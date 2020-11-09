// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use libra_logger::prelude::*;
use once_cell::sync::Lazy;
use std::{sync::Mutex, time::Instant};

static TRACER: Lazy<Mutex<Tracer>> = Lazy::new(|| Mutex::new(Tracer::new()));

pub fn get_trace_block_gen(name: &'static str) -> TraceBlockGen {
    let id = { TRACER.lock().unwrap().lock_block_id() };
    let timer = Instant::now();
    TraceBlockGen { id, name, timer }
}

pub fn print_tracer() {
    let tracer_clone = {
        let mut tracer = TRACER.lock().unwrap();
        let tracer_clone = tracer.clone();
        tracer.clear();
        tracer_clone
    };
    println!("{:#?}", tracer_clone.coalesce());
}

pub fn log_tracer() -> String {
    let tracer_clone = {
        let mut tracer = TRACER.lock().unwrap();
        let tracer_clone = tracer.clone();
        tracer.clear();
        tracer_clone
    };
    format!("{:?}", tracer_clone.coalesce())
}

#[derive(Debug, Clone)]
struct Tracer {
    blocks: Vec<Option<TraceBlock>>,
}

#[derive(Debug, Clone)]
struct TraceBlock {
    name: &'static str,
    time: u128,
}

#[derive(Debug)]
pub struct TraceBlockGen {
    id: usize,
    name: &'static str,
    timer: Instant,
}

#[derive(Debug)]
struct TraceBlockInfo {
    name: &'static str,
    count: usize,
    total: u128,
    min: u128,
    max: u128,
}

impl Tracer {
    fn new() -> Self {
        Tracer { blocks: vec![] }
    }

    fn lock_block_id(&mut self) -> usize {
        let id = self.blocks.len();
        self.blocks.push(None);
        id
    }

    fn clear(&mut self) {
        self.blocks.clear();
    }

    fn coalesce(&self) -> Vec<TraceBlockInfo> {
        let mut block_infos: Vec<TraceBlockInfo> = vec![];
        for block in &self.blocks {
            match block {
                None => error!("found None in TraceBlockInfo"),
                Some(block) => {
                    match block_infos
                        .iter_mut()
                        .find(|block_info| block_info.name == block.name)
                    {
                        None => block_infos.push(TraceBlockInfo::new(block.name, block.time)),
                        Some(block_info) => block_info.add(block),
                    }
                }
            }
        }
        block_infos
    }
}

impl Drop for TraceBlockGen {
    fn drop(&mut self) {
        let time = self.timer.elapsed().as_micros();
        let name = self.name;
        let trace_block = TraceBlock { name, time };
        if let Some(val) = TRACER.lock().unwrap().blocks.get_mut(self.id) {
            *val = Some(trace_block);
        } else {
            error!("no value at index {}", self.id);
        }
    }
}

impl TraceBlockInfo {
    fn new(name: &'static str, value: u128) -> Self {
        TraceBlockInfo {
            name,
            count: 1,
            total: value,
            min: value,
            max: value,
        }
    }

    fn add(&mut self, block: &TraceBlock) {
        self.count += 1;
        self.total += block.time;
        self.min = std::cmp::min(self.min, block.time);
        self.max = std::cmp::max(self.max, block.time);
    }
}
