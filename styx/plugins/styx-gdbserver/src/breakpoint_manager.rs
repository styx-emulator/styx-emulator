// SPDX-License-Identifier: BSD-2-Clause
//! Manages gdb-internal breakpoints for the gdb-plugin
use styx_core::core::VcpuId;
use styx_core::hooks::HookToken;
use styx_core::prelude::log::trace;
use styx_core::sync::sync::atomic::{AtomicBool, Ordering};
use styx_core::sync::sync::{Arc, Mutex, RwLock};
use tracing::debug;

#[derive(Debug, Default, PartialEq, Eq)]
enum BreakpointState {
    #[default]
    Active,
    NotActive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BreakpointFound {
    Found,
    NotFound,
}

impl BreakpointFound {
    pub(crate) fn found(self) -> bool {
        self == BreakpointFound::Found
    }

    pub(crate) fn from_found(is_found: bool) -> Self {
        if is_found {
            BreakpointFound::Found
        } else {
            BreakpointFound::NotFound
        }
    }
}

/// contains all the bp data, only compared and sorted on the
/// address of the breakpoint, not the state or the token
#[derive(Debug)]
struct BpContainer {
    addr: u64,
    /// Currently we just deactivate breakpoints instead of removing them.
    /// If we want to remove them from the cpu backend later we can use these.
    #[allow(dead_code)]
    tokens: Vec<HookToken>,
    state: BreakpointState,
}

impl BpContainer {
    fn from_addr(addr: &u64) -> Self {
        Self {
            addr: *addr,
            tokens: Vec::new(),
            state: BreakpointState::default(),
        }
    }

    pub fn new(tokens: Vec<HookToken>, addr: u64) -> Self {
        Self {
            addr,
            tokens,
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
/// is set then the target emulation is halted at a breakpoint.
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
#[derive(Default, Debug)]
pub struct BreakpointManager {
    paused: AtomicBool,
    paused_address: Arc<Mutex<u64>>,
    paused_vcpu: Arc<Mutex<VcpuId>>,
    /// Addresses of breakpoints from the gdb client. These get reset on each
    /// emulation start/stop.
    ///
    /// Insertions are sorted in place so we can binary search
    /// during `contains`
    breakpoints: Arc<RwLock<Vec<BpContainer>>>,
}

impl BreakpointManager {
    #[cfg(test)]
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

    /// Do we have a deactivated breakpoint at addr?
    pub fn contains_not_active(&self, addr: &u64) -> BreakpointFound {
        let search_item = BpContainer::from_addr(addr);
        let breakpoints = self.breakpoints.read().unwrap();

        // see if we could find a breakpoint with the same address
        // that is not active
        if let Ok(bp_idx) = breakpoints.binary_search(&search_item) {
            return BreakpointFound::from_found(
                breakpoints.get(bp_idx).unwrap().state == BreakpointState::NotActive,
            );
        }

        BreakpointFound::NotFound
    }

    /// Checks if a breakpoint is set at the requested address
    /// (whether active or inactive)
    pub fn contains_breakpoint(&self, addr: &u64) -> bool {
        let search_item = BpContainer::from_addr(addr);
        let breakpoints = self.breakpoints.read().unwrap();

        // see if we could find a breakpoint with the same address
        breakpoints.binary_search(&search_item).is_ok()
    }

    pub fn activate(&self, addr: &u64) -> BreakpointFound {
        let search_item = BpContainer::from_addr(addr);
        let mut breakpoints = self.breakpoints.write().unwrap();

        // see if we could find a breakpoint with the same address
        if let Ok(pos) = breakpoints.binary_search(&search_item) {
            let bp = breakpoints.get_mut(pos).unwrap();

            bp.state = BreakpointState::Active;
            BreakpointFound::Found
        } else {
            // could not find it
            BreakpointFound::NotFound
        }
    }

    /// Deactivates breakpoints at `addr` but does not remove them.
    ///
    /// Returns true if breakpoints were found, otherwise false.
    pub fn deactivate(&self, addr: &u64) -> BreakpointFound {
        let search_item = BpContainer::from_addr(addr);
        let mut breakpoints = self.breakpoints.write().unwrap();

        // see if we could find a breakpoint with the same address
        if let Ok(pos) = breakpoints.binary_search(&search_item) {
            let bp = breakpoints.get_mut(pos).unwrap();

            bp.state = BreakpointState::NotActive;
            trace!("deactivated bp at 0x{addr:X}");
            BreakpointFound::Found
        } else {
            // could not find it
            BreakpointFound::NotFound
        }
    }

    /// Pause at the given address, recording which vCPU triggered it.
    pub fn pause_with_vcpu(&self, addr: u64, vcpu_index: VcpuId) {
        self.paused.store(true, Ordering::Release);
        *self.paused_address.lock().unwrap() = addr;
        *self.paused_vcpu.lock().unwrap() = vcpu_index;
        debug!("BP manager is now paused (vcpu {vcpu_index})");
    }

    /// Returns the vcpu index that triggered the pause, if paused.
    #[cfg(test)]
    pub fn paused_vcpu_index(&self) -> Option<VcpuId> {
        if self.paused.load(Ordering::Acquire) {
            Some(*self.paused_vcpu.lock().unwrap())
        } else {
            None
        }
    }

    /// Sets `self.paused` to `false`, set when we are ready to resume inner
    /// emulation and yield control back to the target emulation
    #[cfg(test)]
    pub fn unpause(&self) {
        self.paused.store(false, Ordering::Release);
        debug!("BP manager is now unpaused");
    }

    /// Gets the current state of `self.paused`
    #[inline]
    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    pub fn add_breakpoint(&self, tokens: Vec<HookToken>, addr: u64) -> bool {
        // TODO: only 1 bp per address for now
        if self.contains_breakpoint(&addr) {
            return false;
        }

        let mut breakpoints = self.breakpoints.write().unwrap();

        // add the breakpoint, and sort the list
        let item = BpContainer::new(tokens, addr);
        breakpoints.push(item);
        breakpoints.sort_unstable();

        true
    }

    /// Removes a breakpoint address from the store, returns the hook tokens.
    ///
    /// Note that the breakpoint should be deleted from the CpuEngine with
    /// the returned tokens.
    #[cfg(test)]
    pub fn remove_breakpoint(&self, addr: u64) -> Result<Vec<HookToken>, ()> {
        let mut breakpoints = self.breakpoints.write().unwrap();
        debug!("BreakpointManager::remove_breakpoint({:#x})", addr);

        let search_item = BpContainer::from_addr(&addr);
        // find the matching bp and return the tokens
        if let Ok(pos) = breakpoints.binary_search(&search_item) {
            let bp = breakpoints.remove(pos);
            Ok(bp.tokens)
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
    fn breakpoint_mgr_pause_with_vcpu() {
        let mgr = BreakpointManager::default();
        assert!(!mgr.paused());
        assert_eq!(None, mgr.paused_vcpu_index());

        mgr.pause_with_vcpu(0x1000, 2);
        assert!(mgr.paused());
        assert_eq!(Some(0x1000), mgr.paused_address());
        assert_eq!(Some(2), mgr.paused_vcpu_index());

        mgr.unpause();
        assert_eq!(None, mgr.paused_vcpu_index());
    }

    #[test]
    fn breakpoint_add() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(vec![hook_token], address));

        // fail add twice to same address
        let hook_token = HookToken::default();
        assert!(!mgr.add_breakpoint(vec![hook_token], address));

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
        assert!(mgr.add_breakpoint(vec![hook_token], address));

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
        assert!(mgr.add_breakpoint(vec![hook_token1], address1));
        assert!(mgr.add_breakpoint(vec![hook_token2], address2));
        assert!(mgr.add_breakpoint(vec![hook_token3], address3));

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
        assert!(mgr.add_breakpoint(vec![hook_token], address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.activate(&address).found());
        // the breakpoint is active
        assert!(mgr.breakpoints.read().unwrap()[0].state == BreakpointState::Active);

        // we fail to activate a breakpoint that does not exist
        assert!(!mgr.activate(&0x99999999).found());
    }

    #[test]
    fn breakpoint_deactivate() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(vec![hook_token], address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.deactivate(&address).found());
        // the breakpoint is not active
        assert!(mgr.breakpoints.read().unwrap()[0].state == BreakpointState::NotActive);

        // we fail to deactivate a breakpoint that does not exist
        assert!(!mgr.deactivate(&0x99999999).found());
    }

    #[test]
    fn breakpoint_contains_active() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(vec![hook_token], address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.activate(&address).found());
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
        assert!(mgr.add_breakpoint(vec![hook_token], address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.activate(&address).found());
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
        assert!(mgr.add_breakpoint(vec![hook_token1], address1));
        assert!(mgr.add_breakpoint(vec![hook_token2], address2));
        assert!(mgr.add_breakpoint(vec![hook_token3], address3));

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
        assert!(mgr.add_breakpoint(vec![hook_token1], address1));
        assert!(mgr.add_breakpoint(vec![hook_token2], address2));
        assert!(mgr.add_breakpoint(vec![hook_token3], address3));

        // at this point `breakpoints` should have length 3
        assert_eq!(3, mgr.breakpoints.read().unwrap().len());

        assert!(mgr.activate(&address1).found());
        // address2 is deactivated
        assert!(mgr.deactivate(&address2).found());
        assert!(mgr.activate(&address3).found());

        // we *do* contain the active addresses, and not the address 2
        assert!(mgr.contains_active(&address1));
        assert!(!mgr.contains_active(&address2));
        assert!(mgr.contains_active(&address3));
    }

    #[test]
    fn breakpoint_contains_not_active() {
        let hook_token = HookToken::default();
        let address = 0x41414141;

        // success add once
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(vec![hook_token], address));

        // at this point `breakpoints` should have length 1
        assert_eq!(1, mgr.breakpoints.read().unwrap().len());
        // the address of the breakpoint should be == address
        assert_eq!(address, mgr.breakpoints.read().unwrap()[0].addr);
        // activate
        assert!(mgr.deactivate(&address).found());
        // the breakpoint is not active
        assert!(mgr.breakpoints.read().unwrap()[0].state == BreakpointState::NotActive);

        // we find a breakpoint that does exist
        assert!(mgr.contains_not_active(&address).found());
        // we fail to find a breakpoint that does not exist
        assert!(!mgr.contains_not_active(&0x99999999).found());
    }

    #[test]
    fn breakpoint_contains_not_active_multiple() {
        let hook_token1 = HookToken::default();
        let hook_token2 = HookToken::default();
        let hook_token3 = HookToken::default();
        let address1 = 0x41414141;
        let address2 = 0x42424242;
        let address3 = 0x43434343;

        // success add breakpoints
        let mgr = BreakpointManager::default();
        assert!(mgr.add_breakpoint(vec![hook_token1], address1));
        assert!(mgr.add_breakpoint(vec![hook_token2], address2));
        assert!(mgr.add_breakpoint(vec![hook_token3], address3));

        // at this point `breakpoints` should have length 3
        assert_eq!(3, mgr.breakpoints.read().unwrap().len());

        // deactivate 1 + 2
        assert!(mgr.deactivate(&address1).found());
        assert!(mgr.deactivate(&address2).found());
        assert!(mgr.activate(&address3).found());

        // we *do* contain the not active addresses, and not the address 3
        assert!(mgr.contains_not_active(&address1).found());
        assert!(mgr.contains_not_active(&address2).found());
        assert!(!mgr.contains_not_active(&address3).found());
    }
}
