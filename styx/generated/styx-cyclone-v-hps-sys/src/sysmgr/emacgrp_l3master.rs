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
#[doc = "Register `emacgrp_l3master` reader"]
pub type R = crate::R<EmacgrpL3masterSpec>;
#[doc = "Register `emacgrp_l3master` writer"]
pub type W = crate::W<EmacgrpL3masterSpec>;
#[doc = "Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Arcache0 {
    #[doc = "0: `0`"]
    NoncacheNonbuff = 0,
    #[doc = "1: `1`"]
    Buff = 1,
    #[doc = "2: `10`"]
    CacheNonalloc = 2,
    #[doc = "3: `11`"]
    CacheBuffNonalloc = 3,
    #[doc = "4: `100`"]
    Reserved1 = 4,
    #[doc = "5: `101`"]
    Reserved2 = 5,
    #[doc = "6: `110`"]
    CacheWrthruRdalloc = 6,
    #[doc = "7: `111`"]
    CacheWrbackRdalloc = 7,
    #[doc = "8: `1000`"]
    Reserved3 = 8,
    #[doc = "9: `1001`"]
    Reserved4 = 9,
    #[doc = "10: `1010`"]
    CacheWrthruWralloc = 10,
    #[doc = "11: `1011`"]
    CacheWrbackWralloc = 11,
    #[doc = "12: `1100`"]
    Reserved5 = 12,
    #[doc = "13: `1101`"]
    Reserved6 = 13,
    #[doc = "14: `1110`"]
    CacheWrthruAlloc = 14,
    #[doc = "15: `1111`"]
    CacheWrbackAlloc = 15,
}
impl From<Arcache0> for u8 {
    #[inline(always)]
    fn from(variant: Arcache0) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Arcache0 {
    type Ux = u8;
}
#[doc = "Field `arcache_0` reader - Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index."]
pub type Arcache0R = crate::FieldReader<Arcache0>;
impl Arcache0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Arcache0 {
        match self.bits {
            0 => Arcache0::NoncacheNonbuff,
            1 => Arcache0::Buff,
            2 => Arcache0::CacheNonalloc,
            3 => Arcache0::CacheBuffNonalloc,
            4 => Arcache0::Reserved1,
            5 => Arcache0::Reserved2,
            6 => Arcache0::CacheWrthruRdalloc,
            7 => Arcache0::CacheWrbackRdalloc,
            8 => Arcache0::Reserved3,
            9 => Arcache0::Reserved4,
            10 => Arcache0::CacheWrthruWralloc,
            11 => Arcache0::CacheWrbackWralloc,
            12 => Arcache0::Reserved5,
            13 => Arcache0::Reserved6,
            14 => Arcache0::CacheWrthruAlloc,
            15 => Arcache0::CacheWrbackAlloc,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noncache_nonbuff(&self) -> bool {
        *self == Arcache0::NoncacheNonbuff
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_buff(&self) -> bool {
        *self == Arcache0::Buff
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_cache_nonalloc(&self) -> bool {
        *self == Arcache0::CacheNonalloc
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_cache_buff_nonalloc(&self) -> bool {
        *self == Arcache0::CacheBuffNonalloc
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_reserved1(&self) -> bool {
        *self == Arcache0::Reserved1
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved2(&self) -> bool {
        *self == Arcache0::Reserved2
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_cache_wrthru_rdalloc(&self) -> bool {
        *self == Arcache0::CacheWrthruRdalloc
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_cache_wrback_rdalloc(&self) -> bool {
        *self == Arcache0::CacheWrbackRdalloc
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_reserved3(&self) -> bool {
        *self == Arcache0::Reserved3
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_reserved4(&self) -> bool {
        *self == Arcache0::Reserved4
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_cache_wrthru_wralloc(&self) -> bool {
        *self == Arcache0::CacheWrthruWralloc
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_cache_wrback_wralloc(&self) -> bool {
        *self == Arcache0::CacheWrbackWralloc
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_reserved5(&self) -> bool {
        *self == Arcache0::Reserved5
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_reserved6(&self) -> bool {
        *self == Arcache0::Reserved6
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_cache_wrthru_alloc(&self) -> bool {
        *self == Arcache0::CacheWrthruAlloc
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_cache_wrback_alloc(&self) -> bool {
        *self == Arcache0::CacheWrbackAlloc
    }
}
#[doc = "Field `arcache_0` writer - Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index."]
pub type Arcache0W<'a, REG> = crate::FieldWriterSafe<'a, REG, 4, Arcache0>;
impl<'a, REG> Arcache0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noncache_nonbuff(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::NoncacheNonbuff)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn buff(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::Buff)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn cache_nonalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::CacheNonalloc)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn cache_buff_nonalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::CacheBuffNonalloc)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn reserved1(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::Reserved1)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved2(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::Reserved2)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn cache_wrthru_rdalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::CacheWrthruRdalloc)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn cache_wrback_rdalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::CacheWrbackRdalloc)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn reserved3(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::Reserved3)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn reserved4(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::Reserved4)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn cache_wrthru_wralloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::CacheWrthruWralloc)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn cache_wrback_wralloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::CacheWrbackWralloc)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn reserved5(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::Reserved5)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn reserved6(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::Reserved6)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn cache_wrthru_alloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::CacheWrthruAlloc)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn cache_wrback_alloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache0::CacheWrbackAlloc)
    }
}
#[doc = "Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Arcache1 {
    #[doc = "0: `0`"]
    NoncacheNonbuff = 0,
    #[doc = "1: `1`"]
    Buff = 1,
    #[doc = "2: `10`"]
    CacheNonalloc = 2,
    #[doc = "3: `11`"]
    CacheBuffNonalloc = 3,
    #[doc = "4: `100`"]
    Reserved1 = 4,
    #[doc = "5: `101`"]
    Reserved2 = 5,
    #[doc = "6: `110`"]
    CacheWrthruRdalloc = 6,
    #[doc = "7: `111`"]
    CacheWrbackRdalloc = 7,
    #[doc = "8: `1000`"]
    Reserved3 = 8,
    #[doc = "9: `1001`"]
    Reserved4 = 9,
    #[doc = "10: `1010`"]
    CacheWrthruWralloc = 10,
    #[doc = "11: `1011`"]
    CacheWrbackWralloc = 11,
    #[doc = "12: `1100`"]
    Reserved5 = 12,
    #[doc = "13: `1101`"]
    Reserved6 = 13,
    #[doc = "14: `1110`"]
    CacheWrthruAlloc = 14,
    #[doc = "15: `1111`"]
    CacheWrbackAlloc = 15,
}
impl From<Arcache1> for u8 {
    #[inline(always)]
    fn from(variant: Arcache1) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Arcache1 {
    type Ux = u8;
}
#[doc = "Field `arcache_1` reader - Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index."]
pub type Arcache1R = crate::FieldReader<Arcache1>;
impl Arcache1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Arcache1 {
        match self.bits {
            0 => Arcache1::NoncacheNonbuff,
            1 => Arcache1::Buff,
            2 => Arcache1::CacheNonalloc,
            3 => Arcache1::CacheBuffNonalloc,
            4 => Arcache1::Reserved1,
            5 => Arcache1::Reserved2,
            6 => Arcache1::CacheWrthruRdalloc,
            7 => Arcache1::CacheWrbackRdalloc,
            8 => Arcache1::Reserved3,
            9 => Arcache1::Reserved4,
            10 => Arcache1::CacheWrthruWralloc,
            11 => Arcache1::CacheWrbackWralloc,
            12 => Arcache1::Reserved5,
            13 => Arcache1::Reserved6,
            14 => Arcache1::CacheWrthruAlloc,
            15 => Arcache1::CacheWrbackAlloc,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noncache_nonbuff(&self) -> bool {
        *self == Arcache1::NoncacheNonbuff
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_buff(&self) -> bool {
        *self == Arcache1::Buff
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_cache_nonalloc(&self) -> bool {
        *self == Arcache1::CacheNonalloc
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_cache_buff_nonalloc(&self) -> bool {
        *self == Arcache1::CacheBuffNonalloc
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_reserved1(&self) -> bool {
        *self == Arcache1::Reserved1
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved2(&self) -> bool {
        *self == Arcache1::Reserved2
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_cache_wrthru_rdalloc(&self) -> bool {
        *self == Arcache1::CacheWrthruRdalloc
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_cache_wrback_rdalloc(&self) -> bool {
        *self == Arcache1::CacheWrbackRdalloc
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_reserved3(&self) -> bool {
        *self == Arcache1::Reserved3
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_reserved4(&self) -> bool {
        *self == Arcache1::Reserved4
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_cache_wrthru_wralloc(&self) -> bool {
        *self == Arcache1::CacheWrthruWralloc
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_cache_wrback_wralloc(&self) -> bool {
        *self == Arcache1::CacheWrbackWralloc
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_reserved5(&self) -> bool {
        *self == Arcache1::Reserved5
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_reserved6(&self) -> bool {
        *self == Arcache1::Reserved6
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_cache_wrthru_alloc(&self) -> bool {
        *self == Arcache1::CacheWrthruAlloc
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_cache_wrback_alloc(&self) -> bool {
        *self == Arcache1::CacheWrbackAlloc
    }
}
#[doc = "Field `arcache_1` writer - Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index."]
pub type Arcache1W<'a, REG> = crate::FieldWriterSafe<'a, REG, 4, Arcache1>;
impl<'a, REG> Arcache1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noncache_nonbuff(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::NoncacheNonbuff)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn buff(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::Buff)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn cache_nonalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::CacheNonalloc)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn cache_buff_nonalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::CacheBuffNonalloc)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn reserved1(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::Reserved1)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved2(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::Reserved2)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn cache_wrthru_rdalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::CacheWrthruRdalloc)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn cache_wrback_rdalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::CacheWrbackRdalloc)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn reserved3(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::Reserved3)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn reserved4(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::Reserved4)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn cache_wrthru_wralloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::CacheWrthruWralloc)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn cache_wrback_wralloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::CacheWrbackWralloc)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn reserved5(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::Reserved5)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn reserved6(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::Reserved6)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn cache_wrthru_alloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::CacheWrthruAlloc)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn cache_wrback_alloc(self) -> &'a mut crate::W<REG> {
        self.variant(Arcache1::CacheWrbackAlloc)
    }
}
#[doc = "Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Awcache0 {
    #[doc = "0: `0`"]
    NoncacheNonbuff = 0,
    #[doc = "1: `1`"]
    Buff = 1,
    #[doc = "2: `10`"]
    CacheNonalloc = 2,
    #[doc = "3: `11`"]
    CacheBuffNonalloc = 3,
    #[doc = "4: `100`"]
    Reserved1 = 4,
    #[doc = "5: `101`"]
    Reserved2 = 5,
    #[doc = "6: `110`"]
    CacheWrthruRdalloc = 6,
    #[doc = "7: `111`"]
    CacheWrbackRdalloc = 7,
    #[doc = "8: `1000`"]
    Reserved3 = 8,
    #[doc = "9: `1001`"]
    Reserved4 = 9,
    #[doc = "10: `1010`"]
    CacheWrthruWralloc = 10,
    #[doc = "11: `1011`"]
    CacheWrbackWralloc = 11,
    #[doc = "12: `1100`"]
    Reserved5 = 12,
    #[doc = "13: `1101`"]
    Reserved6 = 13,
    #[doc = "14: `1110`"]
    CacheWrthruAlloc = 14,
    #[doc = "15: `1111`"]
    CacheWrbackAlloc = 15,
}
impl From<Awcache0> for u8 {
    #[inline(always)]
    fn from(variant: Awcache0) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Awcache0 {
    type Ux = u8;
}
#[doc = "Field `awcache_0` reader - Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index."]
pub type Awcache0R = crate::FieldReader<Awcache0>;
impl Awcache0R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Awcache0 {
        match self.bits {
            0 => Awcache0::NoncacheNonbuff,
            1 => Awcache0::Buff,
            2 => Awcache0::CacheNonalloc,
            3 => Awcache0::CacheBuffNonalloc,
            4 => Awcache0::Reserved1,
            5 => Awcache0::Reserved2,
            6 => Awcache0::CacheWrthruRdalloc,
            7 => Awcache0::CacheWrbackRdalloc,
            8 => Awcache0::Reserved3,
            9 => Awcache0::Reserved4,
            10 => Awcache0::CacheWrthruWralloc,
            11 => Awcache0::CacheWrbackWralloc,
            12 => Awcache0::Reserved5,
            13 => Awcache0::Reserved6,
            14 => Awcache0::CacheWrthruAlloc,
            15 => Awcache0::CacheWrbackAlloc,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noncache_nonbuff(&self) -> bool {
        *self == Awcache0::NoncacheNonbuff
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_buff(&self) -> bool {
        *self == Awcache0::Buff
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_cache_nonalloc(&self) -> bool {
        *self == Awcache0::CacheNonalloc
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_cache_buff_nonalloc(&self) -> bool {
        *self == Awcache0::CacheBuffNonalloc
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_reserved1(&self) -> bool {
        *self == Awcache0::Reserved1
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved2(&self) -> bool {
        *self == Awcache0::Reserved2
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_cache_wrthru_rdalloc(&self) -> bool {
        *self == Awcache0::CacheWrthruRdalloc
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_cache_wrback_rdalloc(&self) -> bool {
        *self == Awcache0::CacheWrbackRdalloc
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_reserved3(&self) -> bool {
        *self == Awcache0::Reserved3
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_reserved4(&self) -> bool {
        *self == Awcache0::Reserved4
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_cache_wrthru_wralloc(&self) -> bool {
        *self == Awcache0::CacheWrthruWralloc
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_cache_wrback_wralloc(&self) -> bool {
        *self == Awcache0::CacheWrbackWralloc
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_reserved5(&self) -> bool {
        *self == Awcache0::Reserved5
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_reserved6(&self) -> bool {
        *self == Awcache0::Reserved6
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_cache_wrthru_alloc(&self) -> bool {
        *self == Awcache0::CacheWrthruAlloc
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_cache_wrback_alloc(&self) -> bool {
        *self == Awcache0::CacheWrbackAlloc
    }
}
#[doc = "Field `awcache_0` writer - Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index."]
pub type Awcache0W<'a, REG> = crate::FieldWriterSafe<'a, REG, 4, Awcache0>;
impl<'a, REG> Awcache0W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noncache_nonbuff(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::NoncacheNonbuff)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn buff(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::Buff)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn cache_nonalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::CacheNonalloc)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn cache_buff_nonalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::CacheBuffNonalloc)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn reserved1(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::Reserved1)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved2(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::Reserved2)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn cache_wrthru_rdalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::CacheWrthruRdalloc)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn cache_wrback_rdalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::CacheWrbackRdalloc)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn reserved3(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::Reserved3)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn reserved4(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::Reserved4)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn cache_wrthru_wralloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::CacheWrthruWralloc)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn cache_wrback_wralloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::CacheWrbackWralloc)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn reserved5(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::Reserved5)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn reserved6(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::Reserved6)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn cache_wrthru_alloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::CacheWrthruAlloc)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn cache_wrback_alloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache0::CacheWrbackAlloc)
    }
}
#[doc = "Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index.\n\nValue on reset: 0"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Awcache1 {
    #[doc = "0: `0`"]
    NoncacheNonbuff = 0,
    #[doc = "1: `1`"]
    Buff = 1,
    #[doc = "2: `10`"]
    CacheNonalloc = 2,
    #[doc = "3: `11`"]
    CacheBuffNonalloc = 3,
    #[doc = "4: `100`"]
    Reserved1 = 4,
    #[doc = "5: `101`"]
    Reserved2 = 5,
    #[doc = "6: `110`"]
    CacheWrthruRdalloc = 6,
    #[doc = "7: `111`"]
    CacheWrbackRdalloc = 7,
    #[doc = "8: `1000`"]
    Reserved3 = 8,
    #[doc = "9: `1001`"]
    Reserved4 = 9,
    #[doc = "10: `1010`"]
    CacheWrthruWralloc = 10,
    #[doc = "11: `1011`"]
    CacheWrbackWralloc = 11,
    #[doc = "12: `1100`"]
    Reserved5 = 12,
    #[doc = "13: `1101`"]
    Reserved6 = 13,
    #[doc = "14: `1110`"]
    CacheWrthruAlloc = 14,
    #[doc = "15: `1111`"]
    CacheWrbackAlloc = 15,
}
impl From<Awcache1> for u8 {
    #[inline(always)]
    fn from(variant: Awcache1) -> Self {
        variant as _
    }
}
impl crate::FieldSpec for Awcache1 {
    type Ux = u8;
}
#[doc = "Field `awcache_1` reader - Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index."]
pub type Awcache1R = crate::FieldReader<Awcache1>;
impl Awcache1R {
    #[doc = "Get enumerated values variant"]
    #[inline(always)]
    pub const fn variant(&self) -> Awcache1 {
        match self.bits {
            0 => Awcache1::NoncacheNonbuff,
            1 => Awcache1::Buff,
            2 => Awcache1::CacheNonalloc,
            3 => Awcache1::CacheBuffNonalloc,
            4 => Awcache1::Reserved1,
            5 => Awcache1::Reserved2,
            6 => Awcache1::CacheWrthruRdalloc,
            7 => Awcache1::CacheWrbackRdalloc,
            8 => Awcache1::Reserved3,
            9 => Awcache1::Reserved4,
            10 => Awcache1::CacheWrthruWralloc,
            11 => Awcache1::CacheWrbackWralloc,
            12 => Awcache1::Reserved5,
            13 => Awcache1::Reserved6,
            14 => Awcache1::CacheWrthruAlloc,
            15 => Awcache1::CacheWrbackAlloc,
            _ => unreachable!(),
        }
    }
    #[doc = "`0`"]
    #[inline(always)]
    pub fn is_noncache_nonbuff(&self) -> bool {
        *self == Awcache1::NoncacheNonbuff
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn is_buff(&self) -> bool {
        *self == Awcache1::Buff
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn is_cache_nonalloc(&self) -> bool {
        *self == Awcache1::CacheNonalloc
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn is_cache_buff_nonalloc(&self) -> bool {
        *self == Awcache1::CacheBuffNonalloc
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn is_reserved1(&self) -> bool {
        *self == Awcache1::Reserved1
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn is_reserved2(&self) -> bool {
        *self == Awcache1::Reserved2
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn is_cache_wrthru_rdalloc(&self) -> bool {
        *self == Awcache1::CacheWrthruRdalloc
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn is_cache_wrback_rdalloc(&self) -> bool {
        *self == Awcache1::CacheWrbackRdalloc
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn is_reserved3(&self) -> bool {
        *self == Awcache1::Reserved3
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn is_reserved4(&self) -> bool {
        *self == Awcache1::Reserved4
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn is_cache_wrthru_wralloc(&self) -> bool {
        *self == Awcache1::CacheWrthruWralloc
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn is_cache_wrback_wralloc(&self) -> bool {
        *self == Awcache1::CacheWrbackWralloc
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn is_reserved5(&self) -> bool {
        *self == Awcache1::Reserved5
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn is_reserved6(&self) -> bool {
        *self == Awcache1::Reserved6
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn is_cache_wrthru_alloc(&self) -> bool {
        *self == Awcache1::CacheWrthruAlloc
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn is_cache_wrback_alloc(&self) -> bool {
        *self == Awcache1::CacheWrbackAlloc
    }
}
#[doc = "Field `awcache_1` writer - Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index."]
pub type Awcache1W<'a, REG> = crate::FieldWriterSafe<'a, REG, 4, Awcache1>;
impl<'a, REG> Awcache1W<'a, REG>
where
    REG: crate::Writable + crate::RegisterSpec,
    REG::Ux: From<u8>,
{
    #[doc = "`0`"]
    #[inline(always)]
    pub fn noncache_nonbuff(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::NoncacheNonbuff)
    }
    #[doc = "`1`"]
    #[inline(always)]
    pub fn buff(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::Buff)
    }
    #[doc = "`10`"]
    #[inline(always)]
    pub fn cache_nonalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::CacheNonalloc)
    }
    #[doc = "`11`"]
    #[inline(always)]
    pub fn cache_buff_nonalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::CacheBuffNonalloc)
    }
    #[doc = "`100`"]
    #[inline(always)]
    pub fn reserved1(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::Reserved1)
    }
    #[doc = "`101`"]
    #[inline(always)]
    pub fn reserved2(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::Reserved2)
    }
    #[doc = "`110`"]
    #[inline(always)]
    pub fn cache_wrthru_rdalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::CacheWrthruRdalloc)
    }
    #[doc = "`111`"]
    #[inline(always)]
    pub fn cache_wrback_rdalloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::CacheWrbackRdalloc)
    }
    #[doc = "`1000`"]
    #[inline(always)]
    pub fn reserved3(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::Reserved3)
    }
    #[doc = "`1001`"]
    #[inline(always)]
    pub fn reserved4(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::Reserved4)
    }
    #[doc = "`1010`"]
    #[inline(always)]
    pub fn cache_wrthru_wralloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::CacheWrthruWralloc)
    }
    #[doc = "`1011`"]
    #[inline(always)]
    pub fn cache_wrback_wralloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::CacheWrbackWralloc)
    }
    #[doc = "`1100`"]
    #[inline(always)]
    pub fn reserved5(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::Reserved5)
    }
    #[doc = "`1101`"]
    #[inline(always)]
    pub fn reserved6(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::Reserved6)
    }
    #[doc = "`1110`"]
    #[inline(always)]
    pub fn cache_wrthru_alloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::CacheWrthruAlloc)
    }
    #[doc = "`1111`"]
    #[inline(always)]
    pub fn cache_wrback_alloc(self) -> &'a mut crate::W<REG> {
        self.variant(Awcache1::CacheWrbackAlloc)
    }
}
impl R {
    #[doc = "Bits 0:3 - Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    pub fn arcache_0(&self) -> Arcache0R {
        Arcache0R::new((self.bits & 0x0f) as u8)
    }
    #[doc = "Bits 4:7 - Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    pub fn arcache_1(&self) -> Arcache1R {
        Arcache1R::new(((self.bits >> 4) & 0x0f) as u8)
    }
    #[doc = "Bits 8:11 - Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    pub fn awcache_0(&self) -> Awcache0R {
        Awcache0R::new(((self.bits >> 8) & 0x0f) as u8)
    }
    #[doc = "Bits 12:15 - Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    pub fn awcache_1(&self) -> Awcache1R {
        Awcache1R::new(((self.bits >> 12) & 0x0f) as u8)
    }
}
impl W {
    #[doc = "Bits 0:3 - Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    #[must_use]
    pub fn arcache_0(&mut self) -> Arcache0W<EmacgrpL3masterSpec> {
        Arcache0W::new(self, 0)
    }
    #[doc = "Bits 4:7 - Specifies the values of the 2 EMAC ARCACHE signals. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    #[must_use]
    pub fn arcache_1(&mut self) -> Arcache1W<EmacgrpL3masterSpec> {
        Arcache1W::new(self, 4)
    }
    #[doc = "Bits 8:11 - Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    #[must_use]
    pub fn awcache_0(&mut self) -> Awcache0W<EmacgrpL3masterSpec> {
        Awcache0W::new(self, 8)
    }
    #[doc = "Bits 12:15 - Specifies the values of the 2 EMAC AWCACHE signals. The field array index corresponds to the EMAC index."]
    #[inline(always)]
    #[must_use]
    pub fn awcache_1(&mut self) -> Awcache1W<EmacgrpL3masterSpec> {
        Awcache1W::new(self, 12)
    }
}
#[doc = "Controls the L3 master ARCACHE and AWCACHE AXI signals. These register bits should be updated only during system initialization prior to removing the peripheral from reset. They may not be changed dynamically during peripheral operation All fields are reset by a cold or warm reset.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`emacgrp_l3master::R`](R).  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`emacgrp_l3master::W`](W). You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api)."]
pub struct EmacgrpL3masterSpec;
impl crate::RegisterSpec for EmacgrpL3masterSpec {
    type Ux = u32;
    const OFFSET: u64 = 100u64;
}
#[doc = "`read()` method returns [`emacgrp_l3master::R`](R) reader structure"]
impl crate::Readable for EmacgrpL3masterSpec {}
#[doc = "`write(|w| ..)` method takes [`emacgrp_l3master::W`](W) writer structure"]
impl crate::Writable for EmacgrpL3masterSpec {
    type Safety = crate::Unsafe;
    const ZERO_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
    const ONE_TO_MODIFY_FIELDS_BITMAP: u32 = 0;
}
#[doc = "`reset()` method sets emacgrp_l3master to value 0"]
impl crate::Resettable for EmacgrpL3masterSpec {
    const RESET_VALUE: u32 = 0;
}
