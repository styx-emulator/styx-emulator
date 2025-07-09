// SPDX-License-Identifier: BSD-2-Clause

use mockall::mock;
use std::borrow::Cow;
use styx_errors::styx_loader::StyxLoaderError;
use styx_loader::{Loader, LoaderHints, MemoryLoaderDesc};

mock! {
    #[derive(Debug)]
    pub StyxLoader{}

    impl Loader for StyxLoader {
        fn name(&self) -> &'static str;

        fn load_bytes<'a>(
            &self,
            data: Cow<'a, [u8]>,
            hints: LoaderHints,
        ) -> Result<MemoryLoaderDesc, StyxLoaderError>;
    }
}
