// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `modebit` reader"]
pub type R = crate::R<ModebitSpec>;
#[doc = "Register `modebit` writer"]
pub type W = crate::W<ModebitSpec>;
#[doc = "Field `mode` reader - These are the 8 mode bits that are sent to the device following the address bytes if mode bit transmission has been enabled."]
pub type ModeR = crate::FieldReader;
#[doc = "Field `mode` writer - These are the 8 mode bits that are sent to the device following the address bytes if mode bit transmission has been enabled."]
pub type ModeW<'a, REG> = crate::FieldWriter<'a, REG, 8>;
impl R {
    #[doc = "Bits 0:7 - These are the 8 mode bits that are sent to the device following the address bytes if mode bit transmission has been enabled."]
    #[inline(always)]
    pub fn mode(&self) -> ModeR {
        ModeR::new((self.bits & 0xff) as u8)
    }
}
impl W {
    #[doc = "Bits 0:7 - These are the 8 mode bits that are sent to the device following the address bytes if mode bit transmission has been enabled."]
    #[inline(always)]
    #[must_use]
    pub fn mode(&mut self) -> ModeW<ModebitSpec> {
        ModeW::new(self, 0)
    }
}
#[doc = "\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`modebit::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`modebit::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct ModebitSpec;
impl crate::RegisterSpec for ModebitSpec {
    type Ux = u32;
    const OFFSET: u64 = 40u64;
}
#[doc = "`read()` method returns [`modebit::R`](R) reader structure"]
impl crate::Readable for ModebitSpec {}
#[doc = "`write(|w| ..)` method takes [`modebit::W`](W) writer structure"]
impl crate::Writable for ModebitSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets modebit to value 0"]
impl crate::Resettable for ModebitSpec {
    const RESET_VALUE: u32 = 0;
}
