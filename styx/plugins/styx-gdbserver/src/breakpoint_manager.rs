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
//! Manages gdb-internal breakpoints for the gdb-plugin
use styx_core::hooks::HookToken;
use styx_core::sync::sync::atomic::{AtomicBool, Ordering};
use styx_core::sync::sync::{Arc, Mutex, RwLock};
use tracing::debug;

#[derive(Debug, Default, PartialEq, Eq)]
enum BreakpointState {
    #[default]
    Active,
    Deactive,
}

/// contains all the bp data, only compared and sorted on the
/// address of the breakpoint, not the state or the token
#[derive(Debug)]
struct BpContainer {
    addr: u64,
    token: HookToken,
    state: BreakpointState,
}

impl BpContainer {
    fn from_addr(addr: &u64) -> Self {
        Self {
            addr: *addr,
            token: HookToken::default(),
            state: BreakpointState::default(),
        }
    }

    pub fn new(token: HookToken, addr: u64) -> Self {
        Self {
            addr,
            token,
            state: BreakpointState::default(),
        }
    }
}

impl PartialEq for BpContainer {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl Eq for BpContainer {}

impl PartialOrd for BpContainer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BpContainer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.addr.cmp(&other.addr)
    }
}

/// Used to track the pause state of the gdbstub, when `self.paused`
/// is equal to true then the target emulation is halted at a breakpoint.
///
/// ## Operation
/// In the top level `gdb` plugin, when the user
/// triggers a _resume_ of the emulation (nexti, step, continue),
/// `add_sw_breakpoint` is called. When the cpu finishes the directive
/// (and is stopped) `remove_sw_breakpoint` is called.
///
/// Those two operations map to `activate` and `deactivate` respectively.
/// We don't actually delete the breakpoints from the backing [`CpuBackend`](styx_core::prelude::CpuBackend)
/// so that the backends have the opportunity to benefit from being
/// smart with how breakpoints are stored / managed. Especially since,
/// in the grand scheme of things, the slowdown from gdb won't really
/// notice skipping over breakpoints that are still alive but
/// deactivated.
#[derive(Debug, Default)]
pub struct BreakpointManager {
    paused: AtomicBool,
    paused_address: Arc<Mutex<u64>>,
    /// Addresses of breakpoints from the gdb client. These get reset on each
    /// emulation start/stop.
    ///
    /// Insertions are sorted in place so we can binary search
    /// during `contains`
    breakpoints: Arc<RwLock<Vec<BpContainer>>>,
}

unsafe impl Sync for BreakpointManager {}
unsafe impl Send for BreakpointManager {}

impl BreakpointManager {
    pub fn paused_address(&self) -> Option<u64> {
        if self.paused.load(Ordering::Acquire) {
            return Some(*self.paused_address.lock().unwrap());
        }

        None
    }
    /// Checks if this [`BreakpointManager`] contains a breakpoint
    /// at this address that is *active*
    pub fn contains_active(&self, addr: &u64) -> bool {
        let search_item = BpContainer::from_addr(addr);
        let breakpoints = self.breakpoints.read().unwrap();

        // see if we could find a breakpoint with the same address
        // that is active
        if let Ok(bp_idx) = breakpoints.binary_search(&search_item) {
            return breakpoints.get(bp_idx).unwrap().state == BreakpointState::Active;
        }

        false
    }

    pub fn contains_deactive(&self, addr: &u64) -> bool {
        let search_item = BpContainer::from_addr(addr);
        let breakpoints = self.breakpoints.read().unwrap();

        // see if we could find a breakpoint with the same address
        // that is deactive
        if let Ok(bp_idx) = breakpoints.binary_search(&search_item) {
            return breakpoints.get(bp_idx).unwrap().state == BreakpointState::Deactive;
        }

        false
    }

    /// Checks if a breakpoint is set at the requested address
    /// (whether active or inactive)
    pub fn contains_breakpoint(&self, addr: &u64) -> bool {
        let search_item = BpContainer::from_addr(addr);
        let breakpoints = self.breakpoints.read().unwrap();

        // see if we could find a breakpoint with the same address
        breakpoints.binary_search(&search_item).is_ok()
    }

    pub fn activate(&self, addr: &u64) -> bool {
        let search_item = BpContainer::from_addr(addr);
        let mut breakpoints = self.breakpoints.write().unwrap();

        // see if we could find a breakpoint with the same address
        if let Ok(pos) = breakpoints.binary_search(&search_item) {
            let bp = breakpoints.get_mut(pos).unwrap();

            bp.state = BreakpointState::Active;
            true
        } else {
            // could not find it
            false
        }
    }

    pub fn deactivate(&self, addr: &u64) -> bool {
        let search_item = BpContainer::from_addr(addr);
        let mut breakpoints = self.breakpoints.write().unwrap();

        // see if we could find a breakpoint with the same address
        if let Ok(pos) = breakpoints.binary_search(&search_item) {
            let bp = breakpoints.get_mut(pos).unwrap();

            bp.state = BreakpointState::Deactive;
            true
        } else {
            // could not find it
            false
        }
    }

    /// Sets `self.paused` to `true`, set when the inner emulation pauses
    /// and yields control to us
    #[inline]
    pub fn pause(&self, addr: u64) {
        self.paused.store(true, Ordering::Release);
        *self.paused_address.lock().unwrap() = addr;
        debug!("BP manager is now paused");
    }

    /// Sets `self.paused` to `false`, set when we are ready to resume inner
    /// emulation and yield control back to the target emulation
    #[inline]
    pub fn unpause(&self) {
        self.paused.store(false, Ordering::Release);
        debug!("BP manager is now unpaused");
    }

    /// Gets the current state of `self.paused`
    #[inline]
    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    pub fn add_breakpoint(&self, hook_token: HookToken, addr: u64) -> bool {
        // TODO: only 1 bp per address for now
        if self.contains_breakpoint(&addr) {
            return false;
        }

        let mut breakpoints = self.breakpoints.write().unwrap();

        // add the breakpoint, and sort the list
        let item = BpContainer::new(hook_token, addr);
        breakpoints.push(item);
        breakpoints.sort_unstable();

        true
    }

    /// Removes a breakpoint address from the store, returns bool if removed.
    ///
    /// Note that the breakpoint should be deleted from the CpuEngine with
    /// the returned token
    #[allow(dead_code)]
    pub fn remove_breakpoint(&self, addr: u64) -> Result<HookToken, ()> {
        let mut breakpoints = self.breakpoints.write().unwrap();
        debug!("BreakpointManager::remove_breakpoint({:#x})", addr);

        let search_item = BpContainer::from_addr(&addr);
        // find the matching bp and return the token
        if let Ok(pos) = breakpoints.binary_search(&search_item) {
            let bp = breakpoints.remove(pos);
            Ok(bp.token)
        } else {
            // no bp found
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoint_mgr_pause() {
        let mgr = BreakpointManager::default();

        // default behavior
        assert!(!mgr.paused());

        // now pause
        mgr.pause(0);

        // we are paused
        assert!(mgr.paused());
        assert_eq!(Some(0), mgr.paused_address());
    }

    #[test]
    fn breakpoint_mgr_unpause() {
        let mgr = BreakpointManager::default();
        // set paused
        mgr.pause(0);
        assert!(mgr.paused()); // should be paused at the beginning of the test
        assert_eq!(Some(0), mgr.paused_address());

        // now unpause
        mgr.unpause();
        assert!(!mgr.paused());
        assert_eq!(None, mgr.paused_address());
    }

    #[test]
    fn breakpoint_mgr_paused() {
        let mgr = BreakpointManager::default();

        // they should be the same
        assert_eq!(mgr.paused(), mgr.paused.load(Ordering::Acquire));
        assert_eq!(None, mgr.paused_address());

        // now pause
        mgr.pause(0);
        assert!(mgr.paused());
        assert_eq!(mgr.paused(), mgr.paused.load(Ordering::Acquire));
        assert_eq!(Some(0), mgr.paused_address());

        // now unpause
        mgr.unpause();
        assert!(!mgr.paused());
        assert_eq!(mgr.paused(), mgr.paused.load(Ordering::Acquire));
        assert_eq!(None, mgr.paused_address());
    }

    #[test]
    fn breakpoint_add() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token, address));

        // fail add twice to same address
        let hook_token = HookToken::default();
        assert!(!mgr.add_breakpoint(hook_token, address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
    }

    #[test]
    fn breakpoint_contains() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token, address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // we *do* contain the address
        assert!(mgr.contains_breakpoint(&address));
        // we *do not* contain a different address
        assert!(!mgr.contains_breakpoint(&0x81818181));
    }

    #[test]
    fn breakpoint_contains_multiple() {
        let hook_token1 = HookToken::default();
        let hook_token2 = HookToken::default();
        let hook_token3 = HookToken::default();
        let address1 = 0x41414141;
        let address2 = 0x42424242;
        let address3 = 0x43434343;

        // success add breakpoints
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token1, address1));
        assert!(mgr.add_breakpoint(hook_token2, address2));
        assert!(mgr.add_breakpoint(hook_token3, address3));

        // at this point `breakpoints` should have length 3
        assert_eq!(3, mgr.breakpoints.read().unwrap().len());

        // we *do* contain the addresses
        assert!(mgr.contains_breakpoint(&address1));
        assert!(mgr.contains_breakpoint(&address2));
        assert!(mgr.contains_breakpoint(&address3));
        // we *do not* contain a different address
        assert!(!mgr.contains_breakpoint(&0x81818181));
    }

    #[test]
    fn breakpoint_activate() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token, address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.activate(&address));
        // the breakpoint is active
        assert!(mgr.breakpoints.read().unwrap()[0].state == BreakpointState::Active);

        // we fail to activate a breakpoint that does not exist
        assert!(!mgr.activate(&0x99999999));
    }

    #[test]
    fn breakpoint_deactivate() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token, address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.deactivate(&address));
        // the breakpoint is deactive
        assert!(mgr.breakpoints.read().unwrap()[0].state == BreakpointState::Deactive);

        // we fail to deactivate a breakpoint that does not exist
        assert!(!mgr.deactivate(&0x99999999));
    }

    #[test]
    fn breakpoint_contains_active() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token, address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.activate(&address));
        // the breakpoint is active
        assert!(mgr.breakpoints.read().unwrap()[0].state == BreakpointState::Active);

        // we find a breakpoint that does exist
        assert!(mgr.contains_active(&address));
        // we fail to find a breakpoint that does not exist
        assert!(!mgr.contains_active(&0x99999999));
    }

    #[test]
    fn breakpoint_test_remove() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token, address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.activate(&address));
        // the breakpoint is active
        assert!(mgr.breakpoints.read().unwrap()[0].state == BreakpointState::Active);

        // we find a breakpoint that does exist
        assert!(mgr.contains_active(&address));
        // we fail to find a breakpoint that does not exist
        assert!(!mgr.contains_active(&0x99999999));

        // we can delete a breakpoint that does exist
        assert!(mgr.remove_breakpoint(address).is_ok());
        // we fail to delete a breakpoint that does not exist
        assert!(mgr.remove_breakpoint(0x99999999).is_err());
    }

    #[test]
    fn breakpoint_remove_multiple() {
        let hook_token1 = HookToken::default();
        let hook_token2 = HookToken::default();
        let hook_token3 = HookToken::default();
        let address1 = 0x41414141;
        let address2 = 0x42424242;
        let address3 = 0x43434343;

        // success add breakpoints
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token1, address1));
        assert!(mgr.add_breakpoint(hook_token2, address2));
        assert!(mgr.add_breakpoint(hook_token3, address3));

        // at this point `breakpoints` should have length 3
        assert_eq!(3, mgr.breakpoints.read().unwrap().len());

        // we *do* contain the three breakpoints
        assert!(mgr.contains_active(&address1));
        assert!(mgr.contains_breakpoint(&address2));
        assert!(mgr.contains_active(&address3));

        // we cannot remove breakpoints that do not exist
        assert!(mgr.remove_breakpoint(0x99999999).is_err());
        assert!(mgr.remove_breakpoint(0x15151515).is_err());

        // we can successfully remove all the breakpoints
        // that do exist
        assert!(mgr.remove_breakpoint(address1).is_ok());
        assert!(mgr.remove_breakpoint(address2).is_ok());
        assert!(mgr.remove_breakpoint(address3).is_ok());
    }

    #[test]
    fn breakpoint_contains_active_multiple() {
        let hook_token1 = HookToken::default();
        let hook_token2 = HookToken::default();
        let hook_token3 = HookToken::default();
        let address1 = 0x41414141;
        let address2 = 0x42424242;
        let address3 = 0x43434343;

        // success add breakpoints
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token1, address1));
        assert!(mgr.add_breakpoint(hook_token2, address2));
        assert!(mgr.add_breakpoint(hook_token3, address3));

        // at this point `breakpoints` should have length 3
        assert_eq!(3, mgr.breakpoints.read().unwrap().len());

        assert!(mgr.activate(&address1));
        // address2 is deactivated
        assert!(mgr.deactivate(&address2));
        assert!(mgr.activate(&address3));

        // we *do* contain the active addresses, and not the address 2
        assert!(mgr.contains_active(&address1));
        assert!(!mgr.contains_active(&address2));
        assert!(mgr.contains_active(&address3));
    }

    #[test]
    fn breakpoint_contains_deactive() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token, address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.deactivate(&address));
        // the breakpoint is deactive
        assert!(mgr.breakpoints.read().unwrap()[0].state == BreakpointState::Deactive);

        // we find a breakpoint that does exist
        assert!(mgr.contains_deactive(&address));
        // we fail to find a breakpoint that does not exist
        assert!(!mgr.contains_deactive(&0x99999999));
    }

    #[test]
    fn breakpoint_contains_deactive_multiple() {
        let hook_token1 = HookToken::default();
        let hook_token2 = HookToken::default();
        let hook_token3 = HookToken::default();
        let address1 = 0x41414141;
        let address2 = 0x42424242;
        let address3 = 0x43434343;

        // success add breakpoints
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(hook_token1, address1));
        assert!(mgr.add_breakpoint(hook_token2, address2));
        assert!(mgr.add_breakpoint(hook_token3, address3));

        // at this point `breakpoints` should have length 3
        assert_eq!(3, mgr.breakpoints.read().unwrap().len());

        // deactivate 1 + 2
        assert!(mgr.deactivate(&address1));
        assert!(mgr.deactivate(&address2));
        assert!(mgr.activate(&address3));

        // we *do* contain the deactive addresses, and not the address 3
        assert!(mgr.contains_deactive(&address1));
        assert!(mgr.contains_deactive(&address2));
        assert!(!mgr.contains_deactive(&address3));
    }
}
