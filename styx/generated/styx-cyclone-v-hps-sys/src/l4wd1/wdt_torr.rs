// SPDX-License-Identifier: BSD-2-Clause
#[doc = "Register `wdt_torr` reader"]
pub type R = crate::R<WdtTorrSpec>;
#[doc = "Register `wdt_torr` writer"]
pub type W = crate::W<WdtTorrSpec>;
#[doc = "This field is used to select the timeout period from which the watchdog counter restarts. A change of the timeout period takes effect only after the next counter restart (kick). The timeout period (in clocks) is: t = 2**(16 + top)\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Top {
    #[doc = "0: `0`"]
    Timeout64k = 0,
    #[doc = "1: `1`"]
    Timeout128k = 1,
    #[doc = "2: `10`"]
    Timeout256k = 2,
    #[doc = "3: `11`"]
    Timeout512k = 3,
    #[doc = "4: `100`"]
    Timeout1m = 4,
    #[doc = "5: `101`"]
    Timeout2m = 5,
    #[doc = "6: `110`"]
    Timeout4m = 6,
    #[doc = "7: `111`"]
    Timeout8m = 7,
    #[doc = "8: `1000`"]
    Timeout16m = 8,
    #[doc = "9: `1001`"]
    Timeout32m = 9,
    #[doc = "10: `1010`"]
    Timeout64m = 10,
    #[doc = "11: `1011`"]
    Timeout128m = 11,
    #[doc = "12: `1100`"]
    Timeout256m = 12,
    #[doc = "13: `1101`"]
    Timeout512m = 13,
    #[doc = "14: `1110`"]
    Timeout1g = 14,
    #[doc = "15: `1111`"]
    Timeout2g = 15,
}
impl From<Top> for u8 {
    #[inline(always)]
    fn from(variant: Top) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Top {
    type Ux = u8;
}
#[doc = "Field `top` reader - This field is used to select the timeout period from which the watchdog counter restarts. A change of the timeout period takes effect only after the next counter restart (kick). The timeout period (in clocks) is: t = 2**(16 + top)"]
pub type TopR = crate::FieldReader<Top>;
impl TopR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Top {
        match self.bits {
            0 => Top::Timeout64k,
            1 => Top::Timeout128k,
            2 => Top::Timeout256k,
            3 => Top::Timeout512k,
            4 => Top::Timeout1m,
            5 => Top::Timeout2m,
            6 => Top::Timeout4m,
            7 => Top::Timeout8m,
            8 => Top::Timeout16m,
            9 => Top::Timeout32m,
            10 => Top::Timeout64m,
            11 => Top::Timeout128m,
            12 => Top::Timeout256m,
            13 => Top::Timeout512m,
            14 => Top::Timeout1g,
            15 => Top::Timeout2g,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_timeout64k(&self) -> bool {
        *self == Top::Timeout64k
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timeout128k(&self) -> bool {
        *self == Top::Timeout128k
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_timeout256k(&self) -> bool {
        *self == Top::Timeout256k
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_timeout512k(&self) -> bool {
        *self == Top::Timeout512k
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_timeout1m(&self) -> bool {
        *self == Top::Timeout1m
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_timeout2m(&self) -> bool {
        *self == Top::Timeout2m
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_timeout4m(&self) -> bool {
        *self == Top::Timeout4m
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_timeout8m(&self) -> bool {
        *self == Top::Timeout8m
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_timeout16m(&self) -> bool {
        *self == Top::Timeout16m
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_timeout32m(&self) -> bool {
        *self == Top::Timeout32m
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_timeout64m(&self) -> bool {
        *self == Top::Timeout64m
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_timeout128m(&self) -> bool {
        *self == Top::Timeout128m
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_timeout256m(&self) -> bool {
        *self == Top::Timeout256m
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_timeout512m(&self) -> bool {
        *self == Top::Timeout512m
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_timeout1g(&self) -> bool {
        *self == Top::Timeout1g
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_timeout2g(&self) -> bool {
        *self == Top::Timeout2g
    }
}
#[doc = "Field `top` writer - This field is used to select the timeout period from which the watchdog counter restarts. A change of the timeout period takes effect only after the next counter restart (kick). The timeout period (in clocks) is: t = 2**(16 + top)"]
pub type TopW<'a, REG> = crate::FieldWriterSafe<'a, REG, 4, Top>;
impl<'a, REG> TopW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn timeout64k(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout64k)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timeout128k(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout128k)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn timeout256k(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout256k)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn timeout512k(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout512k)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn timeout1m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout1m)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn timeout2m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout2m)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn timeout4m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout4m)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn timeout8m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout8m)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn timeout16m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout16m)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn timeout32m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout32m)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn timeout64m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout64m)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn timeout128m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout128m)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn timeout256m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout256m)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn timeout512m(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout512m)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn timeout1g(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout1g)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn timeout2g(self) -> &'a mut crate::W<REG> {
        self.variant(Top::Timeout2g)
    }
}
#[doc = "Used to select the timeout period that the watchdog counter restarts from for the first counter restart (kick). This register should be written after reset and before the watchdog is enabled. A change of the TOP_INIT is seen only once the watchdog has been enabled, and any change after the first kick is not seen as subsequent kicks use the period specified by the TOP bits. The timeout period (in clocks) is: t = 2**(16 + top_init)\n\nValue on reset: 15"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TopInit {
    #[doc = "0: `0`"]
    Timeout64k = 0,
    #[doc = "1: `1`"]
    Timeout128k = 1,
    #[doc = "2: `10`"]
    Timeout256k = 2,
    #[doc = "3: `11`"]
    Timeout512k = 3,
    #[doc = "4: `100`"]
    Timeout1m = 4,
    #[doc = "5: `101`"]
    Timeout2m = 5,
    #[doc = "6: `110`"]
    Timeout4m = 6,
    #[doc = "7: `111`"]
    Timeout8m = 7,
    #[doc = "8: `1000`"]
    Timeout16m = 8,
    #[doc = "9: `1001`"]
    Timeout32m = 9,
    #[doc = "10: `1010`"]
    Timeout64m = 10,
    #[doc = "11: `1011`"]
    Timeout128m = 11,
    #[doc = "12: `1100`"]
    Timeout256m = 12,
    #[doc = "13: `1101`"]
    Timeout512m = 13,
    #[doc = "14: `1110`"]
    Timeout1g = 14,
    #[doc = "15: `1111`"]
    Timeout2g = 15,
}
impl From<TopInit> for u8 {
    #[inline(always)]
    fn from(variant: TopInit) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for TopInit {
    type Ux = u8;
}
#[doc = "Field `top_init` reader - Used to select the timeout period that the watchdog counter restarts from for the first counter restart (kick). This register should be written after reset and before the watchdog is enabled. A change of the TOP_INIT is seen only once the watchdog has been enabled, and any change after the first kick is not seen as subsequent kicks use the period specified by the TOP bits. The timeout period (in clocks) is: t = 2**(16 + top_init)"]
pub type TopInitR = crate::FieldReader<TopInit>;
impl TopInitR {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> TopInit {
        match self.bits {
            0 => TopInit::Timeout64k,
            1 => TopInit::Timeout128k,
            2 => TopInit::Timeout256k,
            3 => TopInit::Timeout512k,
            4 => TopInit::Timeout1m,
            5 => TopInit::Timeout2m,
            6 => TopInit::Timeout4m,
            7 => TopInit::Timeout8m,
            8 => TopInit::Timeout16m,
            9 => TopInit::Timeout32m,
            10 => TopInit::Timeout64m,
            11 => TopInit::Timeout128m,
            12 => TopInit::Timeout256m,
            13 => TopInit::Timeout512m,
            14 => TopInit::Timeout1g,
            15 => TopInit::Timeout2g,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_timeout64k(&self) -> bool {
        *self == TopInit::Timeout64k
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_timeout128k(&self) -> bool {
        *self == TopInit::Timeout128k
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_timeout256k(&self) -> bool {
        *self == TopInit::Timeout256k
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_timeout512k(&self) -> bool {
        *self == TopInit::Timeout512k
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_timeout1m(&self) -> bool {
        *self == TopInit::Timeout1m
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_timeout2m(&self) -> bool {
        *self == TopInit::Timeout2m
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_timeout4m(&self) -> bool {
        *self == TopInit::Timeout4m
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_timeout8m(&self) -> bool {
        *self == TopInit::Timeout8m
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_timeout16m(&self) -> bool {
        *self == TopInit::Timeout16m
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_timeout32m(&self) -> bool {
        *self == TopInit::Timeout32m
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_timeout64m(&self) -> bool {
        *self == TopInit::Timeout64m
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_timeout128m(&self) -> bool {
        *self == TopInit::Timeout128m
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_timeout256m(&self) -> bool {
        *self == TopInit::Timeout256m
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_timeout512m(&self) -> bool {
        *self == TopInit::Timeout512m
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_timeout1g(&self) -> bool {
        *self == TopInit::Timeout1g
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_timeout2g(&self) -> bool {
        *self == TopInit::Timeout2g
    }
}
#[doc = "Field `top_init` writer - Used to select the timeout period that the watchdog counter restarts from for the first counter restart (kick). This register should be written after reset and before the watchdog is enabled. A change of the TOP_INIT is seen only once the watchdog has been enabled, and any change after the first kick is not seen as subsequent kicks use the period specified by the TOP bits. The timeout period (in clocks) is: t = 2**(16 + top_init)"]
pub type TopInitW<'a, REG> = crate::FieldWriterSafe<'a, REG, 4, TopInit>;
impl<'a, REG> TopInitW<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn timeout64k(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout64k)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn timeout128k(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout128k)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn timeout256k(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout256k)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn timeout512k(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout512k)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn timeout1m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout1m)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn timeout2m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout2m)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn timeout4m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout4m)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn timeout8m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout8m)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn timeout16m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout16m)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn timeout32m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout32m)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn timeout64m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout64m)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn timeout128m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout128m)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn timeout256m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout256m)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn timeout512m(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout512m)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn timeout1g(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout1g)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn timeout2g(self) -> &'a mut crate::W<REG> {
        self.variant(TopInit::Timeout2g)
    }
}
impl R {
    #[doc = "Bits 0:3 - This field is used to select the timeout period from which the watchdog counter restarts. A change of the timeout period takes effect only after the next counter restart (kick). The timeout period (in clocks) is: t = 2**(16 + top)"]
    #[inline(always)]
    pub fn top(&self) -> TopR {
        TopR::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - Used to select the timeout period that the watchdog counter restarts from for the first counter restart (kick). This register should be written after reset and before the watchdog is enabled. A change of the TOP_INIT is seen only once the watchdog has been enabled, and any change after the first kick is not seen as subsequent kicks use the period specified by the TOP bits. The timeout period (in clocks) is: t = 2**(16 + top_init)"]
    #[inline(always)]
    pub fn top_init(&self) -> TopInitR {
        TopInitR::new(((self.bits >> 4) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - This field is used to select the timeout period from which the watchdog counter restarts. A change of the timeout period takes effect only after the next counter restart (kick). The timeout period (in clocks) is: t = 2**(16 + top)"]
    #[inline(always)]
    #[must_use]
    pub fn top(&mut self) -> TopW<WdtTorrSpec> {
        TopW::new(self, 0)
    }
    #[doc = "Bits 4:7 - Used to select the timeout period that the watchdog counter restarts from for the first counter restart (kick). This register should be written after reset and before the watchdog is enabled. A change of the TOP_INIT is seen only once the watchdog has been enabled, and any change after the first kick is not seen as subsequent kicks use the period specified by the TOP bits. The timeout period (in clocks) is: t = 2**(16 + top_init)"]
    #[inline(always)]
    #[must_use]
    pub fn top_init(&mut self) -> TopInitW<WdtTorrSpec> {
        TopInitW::new(self, 4)
    }
}
#[doc = "Contains fields that determine the watchdog timeout.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`wdt_torr::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`wdt_torr::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct WdtTorrSpec;
impl crate::RegisterSpec for WdtTorrSpec {
    type Ux = u32;
    const OFFSET: u64 = 4u64;
}
#[doc = "`read()` method returns [`wdt_torr::R`](R) reader structure"]
impl crate::Readable for WdtTorrSpec {}
#[doc = "`write(|w| ..)` method takes [`wdt_torr::W`](W) writer structure"]
impl crate::Writable for WdtTorrSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets wdt_torr to value 0xff"]
impl crate::Resettable for WdtTorrSpec {
    const RESET_VALUE: u32 = 0xff;
}
