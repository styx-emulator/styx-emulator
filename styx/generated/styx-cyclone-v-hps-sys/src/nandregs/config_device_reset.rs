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
#[doc = "Register `config_device_reset` reader"]
pub type R = crate::R<ConfigDeviceResetSpec>;
#[doc = "Register `config_device_reset` writer"]
pub type W = crate::W<ConfigDeviceResetSpec>;
#[doc = "Field `bank0` reader - Issues reset to bank 0. Controller resets the bit after reset command is issued to device."]
pub type Bank0R = crate::BitReader;
#[doc = "Field `bank0` writer - Issues reset to bank 0. Controller resets the bit after reset command is issued to device."]
pub type Bank0W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bank1` reader - Issues reset to bank 1. Controller resets the bit after reset command is issued to device."]
pub type Bank1R = crate::BitReader;
#[doc = "Field `bank1` writer - Issues reset to bank 1. Controller resets the bit after reset command is issued to device."]
pub type Bank1W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bank2` reader - Issues reset to bank 2. Controller resets the bit after reset command is issued to device."]
pub type Bank2R = crate::BitReader;
#[doc = "Field `bank2` writer - Issues reset to bank 2. Controller resets the bit after reset command is issued to device."]
pub type Bank2W<'a, REG> = crate::BitWriter<'a, REG>;
#[doc = "Field `bank3` reader - Issues reset to bank 3. Controller resets the bit after reset command is issued to device."]
pub type Bank3R = crate::BitReader;
#[doc = "Field `bank3` writer - Issues reset to bank 3. Controller resets the bit after reset command is issued to device."]
pub type Bank3W<'a, REG> = crate::BitWriter<'a, REG>;
impl R {
    #[doc = "Bit 0 - Issues reset to bank 0. Controller resets the bit after reset command is issued to device."]
    #[inline(always)]
    pub fn bank0(&self) -> Bank0R {
        Bank0R::new((self.bits & 1) != 0)
    }
    #[doc = "Bit 1 - Issues reset to bank 1. Controller resets the bit after reset command is issued to device."]
    #[inline(always)]
    pub fn bank1(&self) -> Bank1R {
        Bank1R::new(((self.bits >> 1) & 1) != 0)
    }
    #[doc = "Bit 2 - Issues reset to bank 2. Controller resets the bit after reset command is issued to device."]
    #[inline(always)]
    pub fn bank2(&self) -> Bank2R {
        Bank2R::new(((self.bits >> 2) & 1) != 0)
    }
    #[doc = "Bit 3 - Issues reset to bank 3. Controller resets the bit after reset command is issued to device."]
    #[inline(always)]
    pub fn bank3(&self) -> Bank3R {
        Bank3R::new(((self.bits >> 3) & 1) != 0)
    }
}
impl W {
    #[doc = "Bit 0 - Issues reset to bank 0. Controller resets the bit after reset command is issued to device."]
    #[inline(always)]
    #[must_use]
    pub fn bank0(&mut self) -> Bank0W<ConfigDeviceResetSpec> {
        Bank0W::new(self, 0)
    }
    #[doc = "Bit 1 - Issues reset to bank 1. Controller resets the bit after reset command is issued to device."]
    #[inline(always)]
    #[must_use]
    pub fn bank1(&mut self) -> Bank1W<ConfigDeviceResetSpec> {
        Bank1W::new(self, 1)
    }
    #[doc = "Bit 2 - Issues reset to bank 2. Controller resets the bit after reset command is issued to device."]
    #[inline(always)]
    #[must_use]
    pub fn bank2(&mut self) -> Bank2W<ConfigDeviceResetSpec> {
        Bank2W::new(self, 2)
    }
    #[doc = "Bit 3 - Issues reset to bank 3. Controller resets the bit after reset command is issued to device."]
    #[inline(always)]
    #[must_use]
    pub fn bank3(&mut self) -> Bank3W<ConfigDeviceResetSpec> {
        Bank3W::new(self, 3)
    }
}
#[doc = "Device reset. Controller sends a RESET command to device. Controller resets bit after sending command to device\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`config_device_reset::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`config_device_reset::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ConfigDeviceResetSpec;
impl crate::RegisterSpec for ConfigDeviceResetSpec {
    type Ux = u32;
    const OFFSET: u64 = 0u64;
}
#[doc = "`read()` method returns [`config_device_reset::R`](R) reader structure"]
impl crate::Readable for ConfigDeviceResetSpec {}
#[doc = "`write(|w| ..)` method takes [`config_device_reset::W`](W) writer structure"]
impl crate::Writable for ConfigDeviceResetSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets config_device_reset to value 0"]
impl crate::Resettable for ConfigDeviceResetSpec {
    const RESET_VALUE: u32 = 0;
}
