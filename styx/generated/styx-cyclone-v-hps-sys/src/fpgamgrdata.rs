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
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    data: Data,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - Used to send configuration image to FPGA. The DATA register accepts 4 bytes of the configuration image on each write. The configuration image byte-stream is converted into a 4-byte word with little-endian ordering. If the configuration image is not an integer multiple of 4 bytes, software should pad the configuration image with extra zero bytes to make it an integer multiple of 4 bytes. The FPGA Manager converts the DATA to 16 bits wide when writing CB.DATA for partial reconfiguration. The FPGA Manager waits to transmit the data to the CB until the FPGA is able to receive it. For a full configuration, the FPGA Manager waits until the FPGA exits the Reset Phase and enters the Configuration Phase. For a partial reconfiguration, the FPGA Manager waits until the CB.PR_READY signal indicates that the FPGA is ready."]
    #[inline(always)]
    pub const fn data(&self) -> &Data {
        &self.data
    }
}
#[doc = "data (rw) register accessor: Used to send configuration image to FPGA. The DATA register accepts 4 bytes of the configuration image on each write. The configuration image byte-stream is converted into a 4-byte word with little-endian ordering. If the configuration image is not an integer multiple of 4 bytes, software should pad the configuration image with extra zero bytes to make it an integer multiple of 4 bytes. The FPGA Manager converts the DATA to 16 bits wide when writing CB.DATA for partial reconfiguration. The FPGA Manager waits to transmit the data to the CB until the FPGA is able to receive it. For a full configuration, the FPGA Manager waits until the FPGA exits the Reset Phase and enters the Configuration Phase. For a partial reconfiguration, the FPGA Manager waits until the CB.PR_READY signal indicates that the FPGA is ready.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`data::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`data::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@data`]
module"]
#[doc(alias = "data")]
pub type Data = crate::Reg<data::DataSpec>;
#[doc = "Used to send configuration image to FPGA. The DATA register accepts 4 bytes of the configuration image on each write. The configuration image byte-stream is converted into a 4-byte word with little-endian ordering. If the configuration image is not an integer multiple of 4 bytes, software should pad the configuration image with extra zero bytes to make it an integer multiple of 4 bytes. The FPGA Manager converts the DATA to 16 bits wide when writing CB.DATA for partial reconfiguration. The FPGA Manager waits to transmit the data to the CB until the FPGA is able to receive it. For a full configuration, the FPGA Manager waits until the FPGA exits the Reset Phase and enters the Configuration Phase. For a partial reconfiguration, the FPGA Manager waits until the CB.PR_READY signal indicates that the FPGA is ready."]
pub mod data;
