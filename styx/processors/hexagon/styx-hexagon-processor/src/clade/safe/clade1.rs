// SPDX-License-Identifier: BSD-2-Clause

use std::ffi::c_void;

use styx_core::{
    errors::UnknownError,
    memory::Mmu,
    prelude::{log::info, Context},
};
use styx_hexagon_sys::clade::{
    clade_config_t, clade_error_t_CLADE_OK, clade_init, clade_memblock_t, clade_pd_params,
    clade_read, clade_set_trace,
};
use thiserror::Error;

use crate::clade::safe::alloc;

const NO_DICTIONARIES: usize = 3;
const DICTIONARY_LEN: usize = 0x2000;

#[derive(Debug, Error)]
pub enum CladeError {
    #[error(transparent)]
    Other(#[from] UnknownError),
}

pub struct Clade1 {
    internal: clade_config_t,
    // assume 3 dictionaries. containes each
    dictionaries: [*mut u32; NO_DICTIONARIES],
    pd_params: [clade_pd_params; 4],
}

unsafe impl Send for Clade1 {}

impl Clade1 {
    pub fn new() -> Self {
        let mut s = Self {
            internal: clade_config_t {
                region: 0,
                num_pds: 1,
                lib_version: 0,
                // These are default assumptions.
                // This data doesn't seem to be passed in through the clade peripheral.
                num_dicts: NO_DICTIONARIES as u32,
                dict_len: DICTIONARY_LEN as u32,
                pd_params: std::ptr::null_mut(),
                dicts: std::ptr::null_mut(),
                num_replaceable_words: 0,
                replaceable_words: std::ptr::null_mut(),
                error: clade_error_t_CLADE_OK,
                build_id: 0,
            },
            dictionaries: [std::ptr::null_mut(); NO_DICTIONARIES],
            pd_params: [clade_pd_params::default(); 4],
        };

        unsafe {
            clade_set_trace(0x0);
        }

        s.update_clade_internal();
        s
    }
    fn update_clade_internal(&mut self) {
        self.internal.pd_params = &mut self.pd_params as *mut clade_pd_params;
        unsafe { clade_init(&mut self.internal as *mut clade_config_t) };
    }

    pub fn set_output_addr(&mut self, output_addr: u64) {
        self.internal.region = output_addr;

        self.update_clade_internal();
    }

    pub fn set_compress_section(&mut self, compress_addr: u64) {
        info!("setting comp to {compress_addr:x}");
        self.pd_params[0].comp = compress_addr;

        self.update_clade_internal();
    }

    pub fn set_exc_lo(&mut self, exc_lo: u64) {
        info!("setting exc lo to {exc_lo:x}");
        self.pd_params[0].exc_lo = exc_lo;

        self.update_clade_internal();
    }

    pub fn set_exc_hi(&mut self, exc_hi: u64) {
        info!("setting exc hi to {exc_hi:x}");
        self.pd_params[0].exc_hi = exc_hi;

        self.update_clade_internal();
    }

    // The default assumption is there are
    // 3 dictionaries of 0x2000 size each
    // easier to do arithmetic with a u8
    pub fn set_dict_section(&mut self, dict_base: &mut [u8]) {
        info!("setting dictionaries");
        let mut dict_raw = dict_base.as_mut_ptr();

        self.dictionaries[0] = dict_raw as *mut u32;
        self.dictionaries[1] = unsafe { dict_raw.add(DICTIONARY_LEN) } as *mut u32;
        self.dictionaries[2] = unsafe { dict_raw.add(2 * DICTIONARY_LEN) } as *mut u32;

        self.internal.dicts = self.dictionaries.as_mut_ptr();
        info!("dictionaries at {:p}", self.internal.dicts);

        self.update_clade_internal();
    }

    pub fn extract(
        &mut self,
        mmu: &mut Mmu,
        output_addr: u64,
        len: usize,
    ) -> Result<(), CladeError> {
        info!(
            "clade extract called with output addr {:x} region {:x}",
            output_addr, self.internal.region
        );

        let mut request = clade_memblock_t::default();
        request.addr = output_addr;
        request.wordsize = 1;
        request.len = len as i32;
        request.prev = &mut request as *mut clade_memblock_t;
        request.next = &mut request as *mut clade_memblock_t;

        let memblock_ret = unsafe {
            clade_set_trace(0);
            clade_read(
                &mut request as *mut clade_memblock_t,
                mmu as *mut Mmu as *mut c_void,
                Some(alloc::clade_alloc),
                Some(alloc::clade_lookup),
                Some(alloc::clade_free),
            )
        };
        info!("return is {:?}", memblock_ret);
        unsafe {
            let data_len = (*memblock_ret).len;
            info!("memblock len is {data_len:x}, memblock {:?}", *memblock_ret);

            // NOTE: need to free this.
            let data_buf =
                std::slice::from_raw_parts((*memblock_ret).data, (*memblock_ret).len as usize);
            mmu.write_code(output_addr, data_buf)
                .with_context(|| "couldn't write clade data to MMU")?;
        }

        Ok(())
    }
}
