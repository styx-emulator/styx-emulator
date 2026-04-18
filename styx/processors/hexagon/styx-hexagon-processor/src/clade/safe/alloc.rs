// SPDX-License-Identifier: BSD-2-Clause

use std::alloc::{self, Layout};
use std::ffi::CStr;
use std::mem;
use styx_core::memory::Mmu;
use styx_core::prelude::log::{info, trace};
use styx_hexagon_sys::clade::{clade_error_t, clade_error_t_CLADE_OK, clade_memblock_t};

/// Have a request block. It's a doubly linked circular LL.
/// A -> B -> C -> A
/// Allocate P -> Q -> R -> P as a result. Return P.
pub unsafe extern "C" fn clade_alloc(
    mut request: *mut clade_memblock_t,
    previous: *mut clade_memblock_t,
    mem: *mut ::std::os::raw::c_void,
) -> *mut clade_memblock_t {
    info!("doing clade allocation");

    if (request != std::ptr::null_mut()) {
        let request_orig = request;
        let mut response: *mut clade_memblock_t = std::ptr::null_mut();

        loop {
            // MAllocate some blocks
            let mut allocated = Box::into_raw(Box::new(clade_memblock_t::default()));

            // Link the allocated block to the others.

            // At head
            if response == std::ptr::null_mut() {
                (*allocated).next = allocated;
                (*allocated).prev = allocated;
            }
            // Link inside (at the end of the LL)
            else {
                (*allocated).next = (*response).next;
                (*allocated).prev = response;
                (*response).next = allocated;
            }

            info!(
                "request length is {:x} align u8 {:x}",
                (*request).len as usize,
                mem::align_of::<u8>()
            );

            (*allocated).data = alloc::alloc(
                Layout::from_size_align((*request).len as usize, mem::align_of::<u8>())
                    .expect("Couldn't create layout from size/align"),
            );
            (*allocated).wordsize = (*request).wordsize;
            (*allocated).len = (*request).len;

            response = allocated;
            request = (*request).next;

            if request == request_orig {
                break;
            }
        }

        // Currently at the "tail" and not where the request is
        (*response).next
    } else {
        std::ptr::null_mut()
    }
}

// For each request,
// take addr/len, and get data accordingly.
pub unsafe extern "C" fn clade_lookup(
    mut request: *mut clade_memblock_t,
    mem: *mut ::std::os::raw::c_void,
) -> *mut clade_memblock_t {
    // get our mmu back
    let mut mmu = mem as *mut Mmu;

    trace!(
        "LOOKUP request ID {:?} addr {:x}",
        unsafe { CStr::from_ptr((*request).id.as_mut_ptr()) },
        (*request).addr
    );
    let head = request;

    loop {
        let req_len = (*request).len;
        (*request).data = alloc::alloc(
            Layout::from_size_align(req_len as usize, align_of::<u8>())
                .expect("couldn't create layout to alloc clade memblock request"),
        );

        let data_slice = std::slice::from_raw_parts_mut((*request).data, (*request).len as usize);
        (*mmu)
            .read_data((*request).addr as u64, data_slice)
            .expect("Couldn't read requested data from MMU");

        if (request == head) {
            break;
        }
    }

    // should be equal to head atp
    request
}

pub unsafe extern "C" fn clade_free(blocks: *mut clade_memblock_t) -> clade_error_t {
    trace!("calling clade free");
    let block_head = blocks;
    let mut block_cur = blocks;

    loop {
        // Don't need to drop the actual block structures, just the data

        alloc::dealloc(
            (*block_cur).data,
            Layout::from_size_align((*block_cur).len as usize, mem::align_of::<u8>())
                .expect("Couldn't create layout from size/align"),
        );

        trace!(
            "block_cur next {:x} block_head {:x}",
            (*block_cur).next as u64,
            block_head as u64
        );
        if (*block_cur).next == block_head {
            trace!("breaking");
            break;
        }

        block_cur = (*block_cur).next;
    }

    clade_error_t_CLADE_OK
}
