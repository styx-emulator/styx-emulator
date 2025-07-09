// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `MACRWUFFER` reader"]
pub type R = crate::R<MacrwufferSpec>;
#[doc = "Register `MACRWUFFER` writer"]
pub type W = crate::W<MacrwufferSpec>;
impl core::fmt::Debug for R {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.bits())
    }
}
impl core::fmt::Debug for crate::generic::Reg<MacrwufferSpec> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.read(), f)
    }
}
impl W {}
#[doc = "Ethernet MAC remote wakeup frame filter register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`macrwuffer::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`macrwuffer::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct MacrwufferSpec;
impl crate::RegisterSpec for MacrwufferSpec {
    type Ux = u32;
    const OFFSET: u64 = 96u64;
}
#[doc = "`read()` method returns [`macrwuffer::R`](R) reader structure"]
impl crate::Readable for MacrwufferSpec {}
#[doc = "`write(|w| ..)` method takes [`macrwuffer::W`](W) writer structure"]
impl crate::Writable for MacrwufferSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets MACRWUFFER to value 0xffff_ffff"]
impl crate::Resettable for MacrwufferSpec {
    const RESET_VALUE: u32 = 0xffff_ffff;
}
