// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! Symbols Database

use async_trait::async_trait;
use std::collections::HashMap;
use styx_emulator::grpc::typhunix_interop::symbolic::{
    DataType, Program, ProgramIdentifier, Symbol,
};
use styx_emulator::grpc::typhunix_interop::{
    ConnectMessage, ProgKeyType, ProgramRef as _, Validator as _,
};
use styx_emulator::sync::{Arc, Mutex, MutexGuard};
use tracing::{debug, info, warn};

pub type SubKeyType = (String, String, String);
pub type ArcMapMsgs = Arc<Mutex<HashMap<ProgKeyType, ConnectMessage>>>;
pub type ArcMapSubscribers = Arc<Mutex<HashMap<SubKeyType, StagedItems>>>;
pub type ArcVecSymbol = Arc<Mutex<Vec<Symbol>>>;
pub type ArcVecDataType = Arc<Mutex<Vec<DataType>>>;

macro_rules! msgs {
    ($self: ident) => {
        $self.messages.lock().unwrap()
    };
}

#[derive(Default)]
pub struct SymbolsDB {
    /// A map of ConnectMessages from Ghidra
    messages: ArcMapMsgs,

    /// A map of subscribed clients that want to be notified of changes
    /// to Symbol or DataType items
    change_subscribers: ArcMapSubscribers,

    /// A designated uuid that is a wild card for queries
    wildcard_uuid: Arc<Mutex<String>>,
}

#[async_trait]
pub trait MemoryStore: Send + Sync + 'static {
    /// Return a list of the programs
    async fn programs(&self) -> Vec<Program>;

    /// Return a list of the programs if they match any of the pids
    async fn programs_matching(&self, pids: &[ProgramIdentifier]) -> Vec<Program>;

    /// Return a list of the program identifiers
    async fn program_identifiers(&self) -> Vec<ProgramIdentifier>;

    /// insert the message into the map
    /// Return true if the item got stored, false otherwise
    async fn save_message(&self, cmsg: ConnectMessage) -> bool;

    /// a symbols update
    async fn symbol_change(&self, item: Symbol) -> bool;
    /// a data_type update
    async fn data_type_change(&self, item: DataType) -> bool;

    async fn symbols(&self, program: &Program) -> Vec<Symbol>;
    async fn data_types(&self, program: &Program) -> Vec<DataType>;
}

#[async_trait]
impl MemoryStore for SymbolsDB {
    async fn programs(&self) -> Vec<Program> {
        msgs!(self)
            .values()
            .map(|m| m.program.as_ref().unwrap().clone())
            .collect::<Vec<Program>>()
    }

    async fn programs_matching(&self, pids: &[ProgramIdentifier]) -> Vec<Program> {
        msgs!(self)
            .values()
            .filter(|x| {
                pids.is_empty() || pids.contains(x.program.as_ref().unwrap().pid.as_ref().unwrap())
            })
            .map(|c| c.program.as_ref().unwrap().clone())
            .collect::<Vec<Program>>()
    }

    /// Return a list of registered pids
    async fn program_identifiers(&self) -> Vec<ProgramIdentifier> {
        self.programs()
            .await
            .iter()
            .map(|p| p.pid.to_owned().unwrap())
            .collect::<Vec<ProgramIdentifier>>()
    }

    async fn save_message(&self, cmsg: ConnectMessage) -> bool {
        if cmsg.is_valid() {
            let mut map = msgs!(self);
            let pk = cmsg.get_program_key();
            if map.contains_key(&pk) {
                // remove the old entry
                map.remove(&pk);
            }
            // insert new entry
            map.insert(pk, cmsg);
            true
        } else {
            false
        }
    }

    /// Get / return the buffered `Symbol` objects. If the `updates_only` flag
    /// is set, only return changes for the baseline list of `Symbol`; other-
    /// wise return all symbols.
    async fn symbols(&self, p: &Program) -> Vec<Symbol> {
        let key = p.get_program_key();
        info!(":: fetch_symbols: key=({:?})", key);
        if p.updates_only {
            let cli_ky = (
                p.get_source_id(),
                p.get_program_name(),
                p.client_uuid.to_string(),
            );

            debug!(":: fetch_symbols: cli_ky=({:?})", cli_ky);

            match &self.change_subscribers.lock().unwrap().get(&cli_ky) {
                Some(v) => {
                    let mut data_ref = v.symbols.lock().unwrap();
                    let data = data_ref.clone();
                    // clear the results
                    data_ref.clear();
                    data
                }
                _ => vec![],
            }
        } else {
            match msgs!(self).get(&key) {
                Some(cmsg) => cmsg.symbols.clone(),
                _ => vec![],
            }
        }
    }

    /// Get / return the buffered `DataType` objects. If the `updates_only` flag
    /// is set, only return changes for the baseline list of `DataType`; other-
    /// wise return all data types.
    async fn data_types(&self, p: &Program) -> Vec<DataType> {
        let key = p.get_program_key();
        info!(":: fetch_data_types: key=({:?})", key);
        if p.updates_only {
            let cli_ky = (
                p.get_source_id(),
                p.get_program_name(),
                p.client_uuid.to_string(),
            );
            match &self.change_subscribers.lock().unwrap().get(&cli_ky) {
                Some(v) => {
                    let mut data_ref = v.data_types.lock().unwrap();
                    let data = data_ref.clone();
                    // clear the results
                    data_ref.clear();
                    data
                }
                _ => vec![],
            }
        } else {
            match msgs!(self).get(&key) {
                Some(cmsg) => cmsg.data_types.clone(),
                _ => vec![],
            }
        }
    }

    async fn symbol_change(&self, item: Symbol) -> bool {
        let rslt = item.stage(
            &self.change_subscribers,
            self.wildcard_uuid.lock().unwrap().to_string(),
        );
        item.debug_stage(&self.change_subscribers);
        rslt
    }

    async fn data_type_change(&self, item: DataType) -> bool {
        let rslt = item.stage(
            &self.change_subscribers,
            self.wildcard_uuid.lock().unwrap().to_string(),
        );
        item.debug_stage(&self.change_subscribers);
        rslt
    }
}

/// `StagedItems` represent a set of un-acknowledged changes
/// When things are changed they get `staged` - waiting for [Subscriber] of
/// change to acknowledge them.
/// The [Stager] trait allows enables what *can* be staged.
#[derive(Default)]
pub struct StagedItems {
    pub symbols: ArcVecSymbol,
    pub data_types: ArcVecDataType,
}

/// Stages unset changes for subscribers
pub trait Stager: Send + Sync + 'static {
    fn stage(&self, map: &ArcMapSubscribers, any_sub: String) -> bool;

    fn debug_stage(&self, map: &ArcMapSubscribers) {
        let m = map.lock().unwrap();
        m.keys().for_each(|k| {
            let (x, y, z) = (k.0.clone(), k.1.clone(), k.2.clone());
            let sym_count = m.get(k).unwrap().symbols.lock().unwrap().len();
            let dt_count = m.get(k).unwrap().data_types.lock().unwrap().len();
            info!(
                "    (debug stage): {} {} {}: {} {}",
                x, y, z, sym_count, dt_count
            );
        });
    }

    fn stage_symbol(
        mtx: &MutexGuard<'_, HashMap<SubKeyType, StagedItems>>,
        key_list: &[SubKeyType],
        item: &Symbol,
    ) {
        key_list.iter().for_each(|k| {
            mtx.get(k)
                .unwrap()
                .symbols
                .lock()
                .unwrap()
                .push(item.to_owned());
        });
    }

    fn stage_data_type(
        mtx: &MutexGuard<'_, HashMap<(String, String, String), StagedItems>>,
        key_list: &[SubKeyType],
        item: &DataType,
    ) {
        key_list.iter().for_each(|k| {
            mtx.get(k)
                .unwrap()
                .data_types
                .lock()
                .unwrap()
                .push(item.to_owned());
        });
    }

    /// find keys in the subscriber map that match the item's program ref
    /// # Returns
    /// - a vector of keys in the subscriber map for which the item should be staged
    fn find_mkeys(
        &self,
        p: &ProgramIdentifier,
        type_name: &String,
        any_sub: &String,
        item_name: &String,
        mtx: &MutexGuard<'_, HashMap<(String, String, String), StagedItems>>,
    ) -> Vec<SubKeyType> {
        let pgm_ky = p.get_program_key();
        info!("    stage<{}>: for program: {:?}", type_name, p);
        let mut key_list: Vec<SubKeyType> = vec![];
        if !any_sub.is_empty() {
            info!("    stage<{}> wildcard: for program: {:?}", type_name, p);
            key_list.push(("*".to_string(), "*".to_string(), any_sub.to_string()));
        }
        if p.is_valid() {
            mtx.keys().for_each(|k| {
                if k.0.eq(&pgm_ky.0) && k.1.eq(&pgm_ky.1) {
                    // match - save for this subscriber
                    key_list.push(k.to_owned());
                    info!("    staged {} {}", type_name, item_name);
                }
            });
        }

        key_list
    }
}

impl Stager for Symbol {
    fn stage(&self, map: &ArcMapSubscribers, any_sub: String) -> bool {
        let type_name = "Symbol".to_owned();
        match &self.pid {
            Some(p) => {
                // Lock the map
                let mtx = map.lock().unwrap();
                let key_list = self.find_mkeys(p, &type_name, &any_sub, &self.name, &mtx);
                <Symbol as Stager>::stage_symbol(&mtx, &key_list, self);
                !key_list.is_empty()
            }
            _ => {
                warn!(
                    "Received update for invalid unsupported sparse {}: {:?} - no pid",
                    type_name, self
                );
                false
            }
        }
    }
}

impl Stager for DataType {
    fn stage(&self, map: &ArcMapSubscribers, any_sub: String) -> bool {
        let type_name = "DataType".to_owned();
        match &self.pid {
            Some(p) => {
                // Lock the map
                let mtx = map.lock().unwrap();
                let key_list = self.find_mkeys(p, &type_name, &any_sub, &self.name, &mtx);
                <DataType as Stager>::stage_data_type(&mtx, &key_list, self);
                !key_list.is_empty()
            }
            _ => {
                warn!(
                    "Received update for invalid unsupported sparse {}: {:?} - no pid",
                    type_name, self
                );
                false
            }
        }
    }
}

////// Subscriber //////////

/// Allows consumers subscribe to/unsubscribe from changes in [Program] data
pub trait Subscriber: Send + Sync + 'static {
    fn subscribe(&self, program: Program) -> (bool, String);
    fn un_subscribe(&self, pref: Program) -> (bool, String);
    fn subscriber_count(&self) -> usize;
}

/// Enables a [Subscriber] to see all changes (vs changes to a particular [Program])
pub trait Wildcards: Send + Sync + 'static {
    /// permit wildcards to be used for the instance of the server
    fn enable_wildcards(&self);
    /// getter for whether or not wildcards are enabled
    fn is_wildcard_enabled(&self) -> bool;
    fn get_wildcard(&self) -> String;
}

impl Wildcards for SymbolsDB {
    fn enable_wildcards(&self) {
        info!("Enabling wildcard fetches");
        let (_, subid) = self.subscribe(Program {
            pid: Some(ProgramIdentifier {
                source_id: "*".to_string(),
                name: "*".to_string(),
            }),
            ..Default::default()
        });
        *self.wildcard_uuid.lock().unwrap() = subid;
    }

    fn is_wildcard_enabled(&self) -> bool {
        !self.wildcard_uuid.lock().unwrap().is_empty()
    }

    fn get_wildcard(&self) -> String {
        self.wildcard_uuid.lock().unwrap().to_string()
    }
}

impl Subscriber for SymbolsDB {
    /// Store a new subscriber, with an assigned `uuid`
    ///
    /// # Returns
    /// - (true, uuid) if the subscriber was stored. The assigned `uuid` should
    ///                be used on subsequent calls to get staged changes
    /// - (false, "") otherwise
    ///
    /// # Arguments
    /// * `program` - the desired program
    fn subscribe(&self, program: Program) -> (bool, String) {
        debug!(
            "::subscribe <Subscriber for Program> {:?}",
            program.get_program_key()
        );
        if program.is_valid() {
            let pk = program.get_program_key();
            let pkd = pk.clone();
            let pku = (pk.0, pk.1, uuid::Uuid::new_v4().to_string());

            let pkud = pku.clone();

            debug!(
                "::subscribe <Subscriber for Program> pk: {:?}, pku: {:?}",
                pkd, pkud
            );

            self.change_subscribers.lock().unwrap().insert(
                pku.to_owned(),
                StagedItems {
                    symbols: Arc::new(Mutex::new(Vec::new())),
                    data_types: Arc::new(Mutex::new(Vec::new())),
                },
            );
            (true, pku.2)
        } else {
            (false, "".to_owned())
        }
    }

    /// Remove subscriber identified by `self.client_uuid`
    ///
    /// # Returns
    /// - (true, uuid) if the subscriber existed and was removed
    /// - (false, "") otherwise
    ///
    /// # Arguments
    ///
    /// * `program` - the desired program
    fn un_subscribe(&self, program: Program) -> (bool, String) {
        let mut result = (false, "".to_owned());
        if program.is_valid() && !program.client_uuid.is_empty() {
            let mut pmap = self.change_subscribers.lock().unwrap();
            let pku = (
                program.get_source_id(),
                program.get_program_name(),
                program.client_uuid,
            );
            if pmap.contains_key(&pku) {
                pmap.remove(&pku);
                result = (true, pku.2);
            }
        }
        result
    }

    /// return the total number of subscribers, for all programs
    fn subscriber_count(&self) -> usize {
        self.change_subscribers.lock().unwrap().len()
    }
}

/// get a count of staged items for a particular [Subscriber] identified by `ky`,
/// regardless of the [Program].
/// ## Return a tuple (num_symbols, num_datatypes)
pub fn count_staged_for_triple(ky: &SubKeyType, data: &ArcMapSubscribers) -> (usize, usize) {
    let nsymbols = match data.lock().unwrap().get(ky) {
        Some(x) => x.symbols.lock().unwrap().len(),
        _ => 0,
    };
    let ndatatypes = match data.lock().unwrap().get(ky) {
        Some(x) => x.data_types.lock().unwrap().len(),
        _ => 0,
    };

    (nsymbols, ndatatypes)
}

/// get a count of staged items for a particular [Program]
/// ## Return a tuple (num_symbols, num_datatypes)
pub fn count_staged_for_client(p: Program, data: &ArcMapSubscribers) -> (usize, usize) {
    count_staged_for_triple(
        &(p.get_source_id(), p.get_program_name(), p.client_uuid),
        data,
    )
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_utils;
    use crate::test_utils::*;
    use styx_emulator::grpc::typhunix_interop::symbolic::ProgramIdentifier;
    use test_case::test_case;

    #[test_case(Program::default() ; "empty program is no good")]
    #[test_case(Program {
        pid: Some(ProgramIdentifier::default()),
        ..Default::default()
    } ; "source_id and name are 0-len strings")]
    #[test_case(Program {
        pid: Some(ProgramIdentifier{name: "somename".into(), ..Default::default()}),
        ..Default::default()
    } ; "source_id is 0-len strings")]
    #[test_case(Program {
        pid: Some(ProgramIdentifier{source_id: "".into(),..Default::default()}),
        ..Default::default()
    } ; "name is 0-len strings")]

    fn test_programs_not_valid(p: Program) {
        let cm = ConnectMessage {
            program: Some(p),
            ..Default::default()
        };
        assert!(!cm.is_valid());
    }

    #[test]
    fn test_cm_is_valid() {
        assert!(ConnectMessage {
            program: Some(Program {
                pid: Some(ProgramIdentifier {
                    source_id: String::from("id"),
                    name: String::from("name"),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
        .is_valid());
    }

    #[test]
    fn test_cm_not_valid() {
        assert!(!ConnectMessage {
            ..Default::default()
        }
        .is_valid());
    }

    #[tokio::test]
    async fn test_store_program_state() {
        let dsi = SymbolsDB::default();
        let cm = ConnectMessage {
            program: Some(Program {
                pid: Some(ProgramIdentifier {
                    source_id: String::from("pid1"),
                    name: String::from("name1"),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            cm.get_program_key(),
            (String::from("pid1"), String::from("name1"))
        );
        assert_eq!(dsi.messages.lock().unwrap().len(), 0);
        dsi.save_message(cm.to_owned()).await;
        assert_eq!(dsi.messages.lock().unwrap().len(), 1);
        // assert again is dup key
        dsi.save_message(cm).await;
        assert_eq!(dsi.messages.lock().unwrap().len(), 1);
        // insert a new key

        dsi.save_message(ConnectMessage {
            program: Some(Program {
                pid: Some(ProgramIdentifier {
                    source_id: String::from("pid2"),
                    name: String::from("name2"),
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
        assert_eq!(dsi.messages.lock().unwrap().len(), 2);

        // test invalid messages not inserted
        let badmsg = ConnectMessage::default();
        assert!(!badmsg.is_valid());
        assert!(!dsi.save_message(badmsg).await);
        assert_eq!(dsi.messages.lock().unwrap().len(), 2);
    }

    #[test]
    fn test_store_unstore_subscriber() {
        let mut p1 = new_program("p1_id", "p1_name");
        let dsi = SymbolsDB::default();
        assert_eq!(dsi.subscriber_count(), 0);
        let (status, assigned_id) = dsi.subscribe(p1.to_owned());
        assert!(status);
        assert!(!assigned_id.is_empty());
        assert_eq!(dsi.subscriber_count(), 1);

        // un-store if program.client_uuid **is not** set (harmless)
        for _ in 0..3 {
            let (status, id) = dsi.un_subscribe(p1.to_owned());
            assert!(!status);
            assert!(id.is_empty());
            assert_eq!(dsi.subscriber_count(), 1);
        }

        // its harmless to un-subscribe on a non-existent uuid
        p1.client_uuid = "foo".to_string();
        let (status, id) = dsi.un_subscribe(p1.to_owned());
        assert!(!status);
        assert!(id.is_empty());
        assert_eq!(dsi.subscriber_count(), 1);

        // un-store if program.client_uuid **is** set
        p1.client_uuid = assigned_id;
        let (status, id) = dsi.un_subscribe(p1);
        assert!(status);
        assert!(!id.is_empty());
        assert_eq!(dsi.subscriber_count(), 0);
    }

    #[test]
    fn test_staging() {
        let dsi = SymbolsDB::default();
        // Create a symbol to be emitted to the server
        let symbol = test_utils::random_symbol_with_program();
        // Capture the program ident
        let (source_id, pname): (String, String) = (
            symbol.pid.as_ref().unwrap().source_id.to_string(),
            symbol.pid.as_ref().unwrap().name.to_string(),
        );

        // Subscribe to the program
        let (status, sub_uuid) = dsi.subscribe(new_program(&source_id, &pname));
        assert!(status);
        assert!(!sub_uuid.is_empty());
        let subkey = (source_id, pname, sub_uuid);

        // a plugin emits the symbol, it gets staged and held for our subscriber
        assert_eq!(
            super::count_staged_for_triple(&subkey, &dsi.change_subscribers),
            (0, 0)
        );
        // stage it - count to be sure its been staged.
        symbol.stage(
            &dsi.change_subscribers,
            dsi.wildcard_uuid.lock().unwrap().to_string(),
        );

        assert_eq!(
            count_staged_for_triple(&subkey, &dsi.change_subscribers),
            (1, 0)
        );
    }
}
