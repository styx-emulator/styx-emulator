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
use libc::{c_void, close, dup, ftruncate, memfd_create, mmap, mremap, munmap};
use libc::{MAP_FAILED, MAP_PRIVATE, MAP_SHARED, MREMAP_MAYMOVE, PROT_READ, PROT_WRITE};
use std::io::Error;
use std::slice;
use thiserror::Error;

// file descriptor name, required for memfd_create
// string "styx-cow" as bytes
// doing it this way because currently unable to declare a CString constant
const FD_NAME: *const i8 = [115, 116, 121, 120, 95, 99, 111, 119, 0].as_ptr();

// null pointer constant used in the 'mmap' calls
const NULL: *mut c_void = std::ptr::null_mut();

#[derive(Error, Debug)]
pub enum StyxCowError {
    #[error("Creating a copy of a copy is not allowed.")]
    CopyOfCopyError,
    #[error("OS error: {0}")]
    OSError(String),
}

impl From<std::io::Error> for StyxCowError {
    fn from(value: std::io::Error) -> Self {
        StyxCowError::OSError(format!("{:?}", value))
    }
}

#[derive(Debug)]
pub struct Cow {
    fd: i32,
    ptr: *mut c_void,
    size: usize,
    is_copy: bool,
}

impl Cow {
    /// Creates a new Cow struct with a pointer to memory of size 'size'.
    ///
    /// Creates an anonymous file with 'memfd_create' resizes it with 'ftrunctate'
    /// and then creates a shared mapping with 'mmap'.
    ///
    /// Handles error cases for the libc calls
    pub fn new(size: usize) -> Result<Self, StyxCowError> {
        let fd = unsafe { memfd_create(FD_NAME, 0) };
        if fd == -1 {
            return Err(Error::last_os_error())?;
        }

        if unsafe { ftruncate(fd, size as i64) } == -1 {
            return Err(Error::last_os_error())?;
        };

        let ptr = unsafe { mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) };
        if ptr == MAP_FAILED {
            return Err(Error::last_os_error())?;
        }

        Ok(Self {
            fd,
            ptr,
            size,
            is_copy: false,
        })
    }

    /// Uses 'ftruncate' and 'mremap' to resize the backing file and remap it with the new size
    ///
    /// Handles error cases for the libc calls
    pub fn resize(&mut self, size: usize) -> Result<(), StyxCowError> {
        if unsafe { ftruncate(self.fd, size as i64) } == -1 {
            return Err(Error::last_os_error())?;
        };

        let new_ptr = unsafe { mremap(self.ptr, self.size, size, MREMAP_MAYMOVE) };
        if new_ptr == MAP_FAILED {
            return Err(Error::last_os_error())?;
        }

        self.ptr = new_ptr;
        self.size = size;
        Ok(())
    }

    #[inline]
    unsafe fn ptr_to_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.ptr as *mut u8, self.size)
    }

    /// returns an immutable view of the data
    pub fn get_data(&self) -> &[u8] {
        unsafe { self.ptr_to_slice() }
    }

    #[inline]
    unsafe fn ptr_to_mut_slice(&mut self) -> &mut [u8] {
        slice::from_raw_parts_mut(self.ptr as *mut u8, self.size)
    }

    /// returns a mutable view of the data
    pub fn get_data_mut(&mut self) -> &mut [u8] {
        unsafe { self.ptr_to_mut_slice() }
    }

    /// Creates a private, copy-on-write mapping of the same in memory file
    /// which until written to, acts as a reference to the original mapping.
    ///
    /// returns an error if called on a copy.
    pub fn try_clone(&self) -> Result<Self, StyxCowError> {
        if self.is_copy {
            return Err(StyxCowError::CopyOfCopyError);
        }
        let new_ptr = unsafe {
            mmap(
                NULL,
                self.size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE,
                self.fd,
                0,
            )
        };
        if new_ptr == MAP_FAILED {
            return Err(Error::last_os_error())?;
        }

        let new_fd = unsafe { dup(self.fd) };
        if new_fd == -1 {
            return Err(Error::last_os_error())?;
        }

        Ok(Self {
            fd: new_fd,
            ptr: new_ptr,
            size: self.size,
            is_copy: true,
        })
    }

    pub fn len(&self) -> usize {
        self.size
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Drop for Cow {
    /// unmaps and closes the file
    fn drop(&mut self) {
        if unsafe { munmap(self.ptr, self.size) } == -1 {
            panic!("unmap failed: {:?}", Error::last_os_error());
        }

        if unsafe { close(self.fd) } == -1 {
            panic!("close failed: {:?}", Error::last_os_error());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use libc::{fcntl, F_GETFD};

    #[test]
    #[cfg_attr(miri, ignore)]
    fn resize() {
        // tests resizing
        let mut region = Cow::new(32).unwrap();
        region.resize(64).unwrap();

        assert_eq!(region.get_data().len(), 64);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn clone() {
        // checks if changes to original are present in the copy
        let mut region = Cow::new(16).unwrap();
        region.get_data_mut()[0] = 1;
        region.get_data_mut()[1] = 2;

        let region2 = region.try_clone().unwrap();

        assert_eq!(region2.get_data()[0], 1);
        assert_eq!(region2.get_data()[1], 2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn copy_on_write() {
        // changes to the copy should have no affect on the original
        let mut region = Cow::new(16).unwrap();
        region.get_data_mut()[0] = 10;

        let mut region2 = region.try_clone().unwrap();

        region2.get_data_mut()[0] = 15;

        assert_ne!(region.get_data()[0], 15);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn per_page_cow() {
        // create Cow that occupies 2 pages and clone it
        // until a page in the copy is written to, modifications to
        //    the original are passed through to the copy
        // the page isn't copied until actually written to in the copy
        // this test shows this in action, assumes 4kB pages
        let mut r1 = Cow::new(8 * 1024).unwrap();
        let mut r2 = r1.try_clone().unwrap();

        r1.get_data_mut()[0] = 1;
        r2.get_data_mut()[1] = 2;
        r1.get_data_mut()[1] = 1;

        assert_eq!(r2.get_data()[0], 1);
        assert_eq!(r2.get_data()[1], 2);

        r1.get_data_mut()[4 * 1024] = 1;
        r2.get_data_mut()[4 * 1024 + 1] = 2;
        r1.get_data_mut()[4 * 1024 + 1] = 1;

        assert_eq!(r2.get_data()[4 * 1024], 1);
        assert_eq!(r2.get_data()[4 * 1024 + 1], 2);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[should_panic]
    fn copy_of_copy() {
        // creating a copy of a copy is not allowed
        let r = Cow::new(16).unwrap();
        let r1 = r.try_clone().unwrap();
        let _r2 = r1.try_clone().unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_cleanup() {
        // can't think of a good way to check that munmap was successful
        // so for now just check to see if the file got closed
        let region = Cow::new(32).unwrap();
        let region2 = region.try_clone().unwrap();
        let fd = region.fd;
        let fd2 = region2.fd;
        {
            let _region = region;
        }

        // check if first fd was closed
        let status = unsafe { fcntl(fd, F_GETFD) };
        assert!(status < 0);

        // make sure cloned fd is still open
        let status = unsafe { fcntl(fd2, F_GETFD) };
        assert_eq!(status, 0);

        {
            let _region2 = region2;
        }

        // check that second fd was closed
        let status = unsafe { fcntl(fd2, F_GETFD) };
        assert!(status < 0);
    }
}
