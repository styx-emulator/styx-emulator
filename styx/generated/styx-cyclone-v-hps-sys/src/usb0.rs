// SPDX-License-Identifier: BSD-2-Clause
#[repr(C)]
#[doc = "Register block"]
pub struct RegisterBlock {
    globgrp_gotgctl: GlobgrpGotgctl,
    globgrp_gotgint: GlobgrpGotgint,
    globgrp_gahbcfg: GlobgrpGahbcfg,
    globgrp_gusbcfg: GlobgrpGusbcfg,
    globgrp_grstctl: GlobgrpGrstctl,
    globgrp_gintsts: GlobgrpGintsts,
    globgrp_gintmsk: GlobgrpGintmsk,
    globgrp_grxstsr: GlobgrpGrxstsr,
    globgrp_grxstsp: GlobgrpGrxstsp,
    globgrp_grxfsiz: GlobgrpGrxfsiz,
    globgrp_gnptxfsiz: GlobgrpGnptxfsiz,
    globgrp_gnptxsts: GlobgrpGnptxsts,
    _reserved12: [u8; 0x04],
    globgrp_gpvndctl: GlobgrpGpvndctl,
    globgrp_ggpio: GlobgrpGgpio,
    globgrp_guid: GlobgrpGuid,
    globgrp_gsnpsid: GlobgrpGsnpsid,
    globgrp_ghwcfg1: GlobgrpGhwcfg1,
    globgrp_ghwcfg2: GlobgrpGhwcfg2,
    globgrp_ghwcfg3: GlobgrpGhwcfg3,
    globgrp_ghwcfg4: GlobgrpGhwcfg4,
    _reserved20: [u8; 0x08],
    globgrp_gdfifocfg: GlobgrpGdfifocfg,
    _reserved21: [u8; 0xa0],
    globgrp_hptxfsiz: GlobgrpHptxfsiz,
    globgrp_dieptxf1: GlobgrpDieptxf1,
    globgrp_dieptxf2: GlobgrpDieptxf2,
    globgrp_dieptxf3: GlobgrpDieptxf3,
    globgrp_dieptxf4: GlobgrpDieptxf4,
    globgrp_dieptxf5: GlobgrpDieptxf5,
    globgrp_dieptxf6: GlobgrpDieptxf6,
    globgrp_dieptxf7: GlobgrpDieptxf7,
    globgrp_dieptxf8: GlobgrpDieptxf8,
    globgrp_dieptxf9: GlobgrpDieptxf9,
    globgrp_dieptxf10: GlobgrpDieptxf10,
    globgrp_dieptxf11: GlobgrpDieptxf11,
    globgrp_dieptxf12: GlobgrpDieptxf12,
    globgrp_dieptxf13: GlobgrpDieptxf13,
    globgrp_dieptxf14: GlobgrpDieptxf14,
    globgrp_dieptxf15: GlobgrpDieptxf15,
    _reserved37: [u8; 0x02c0],
    hostgrp_hcfg: HostgrpHcfg,
    hostgrp_hfir: HostgrpHfir,
    hostgrp_hfnum: HostgrpHfnum,
    _reserved40: [u8; 0x04],
    hostgrp_hptxsts: HostgrpHptxsts,
    hostgrp_haint: HostgrpHaint,
    hostgrp_haintmsk: HostgrpHaintmsk,
    hostgrp_hflbaddr: HostgrpHflbaddr,
    _reserved44: [u8; 0x20],
    hostgrp_hprt: HostgrpHprt,
    _reserved45: [u8; 0xbc],
    hostgrp_hcchar0: HostgrpHcchar0,
    hostgrp_hcsplt0: HostgrpHcsplt0,
    hostgrp_hcint0: HostgrpHcint0,
    hostgrp_hcintmsk0: HostgrpHcintmsk0,
    hostgrp_hctsiz0: HostgrpHctsiz0,
    hostgrp_hcdma0: HostgrpHcdma0,
    hostgrp_hcdmab0: HostgrpHcdmab0,
    _reserved52: [u8; 0x04],
    hostgrp_hcchar1: HostgrpHcchar1,
    hostgrp_hcsplt1: HostgrpHcsplt1,
    hostgrp_hcint1: HostgrpHcint1,
    hostgrp_hcintmsk1: HostgrpHcintmsk1,
    hostgrp_hctsiz1: HostgrpHctsiz1,
    hostgrp_hcdma1: HostgrpHcdma1,
    hostgrp_hcdmab1: HostgrpHcdmab1,
    _reserved59: [u8; 0x04],
    hostgrp_hcchar2: HostgrpHcchar2,
    hostgrp_hcsplt2: HostgrpHcsplt2,
    hostgrp_hcint2: HostgrpHcint2,
    hostgrp_hcintmsk2: HostgrpHcintmsk2,
    hostgrp_hctsiz2: HostgrpHctsiz2,
    hostgrp_hcdma2: HostgrpHcdma2,
    hostgrp_hcdmab2: HostgrpHcdmab2,
    _reserved66: [u8; 0x04],
    hostgrp_hcchar3: HostgrpHcchar3,
    hostgrp_hcsplt3: HostgrpHcsplt3,
    hostgrp_hcint3: HostgrpHcint3,
    hostgrp_hcintmsk3: HostgrpHcintmsk3,
    hostgrp_hctsiz3: HostgrpHctsiz3,
    hostgrp_hcdma3: HostgrpHcdma3,
    hostgrp_hcdmab3: HostgrpHcdmab3,
    _reserved73: [u8; 0x04],
    hostgrp_hcchar4: HostgrpHcchar4,
    hostgrp_hcsplt4: HostgrpHcsplt4,
    hostgrp_hcint4: HostgrpHcint4,
    hostgrp_hcintmsk4: HostgrpHcintmsk4,
    hostgrp_hctsiz4: HostgrpHctsiz4,
    hostgrp_hcdma4: HostgrpHcdma4,
    hostgrp_hcdmab4: HostgrpHcdmab4,
    _reserved80: [u8; 0x04],
    hostgrp_hcchar5: HostgrpHcchar5,
    hostgrp_hcsplt5: HostgrpHcsplt5,
    hostgrp_hcint5: HostgrpHcint5,
    hostgrp_hcintmsk5: HostgrpHcintmsk5,
    hostgrp_hctsiz5: HostgrpHctsiz5,
    hostgrp_hcdma5: HostgrpHcdma5,
    hostgrp_hcdmab5: HostgrpHcdmab5,
    _reserved87: [u8; 0x04],
    hostgrp_hcchar6: HostgrpHcchar6,
    hostgrp_hcsplt6: HostgrpHcsplt6,
    hostgrp_hcint6: HostgrpHcint6,
    hostgrp_hcintmsk6: HostgrpHcintmsk6,
    hostgrp_hctsiz6: HostgrpHctsiz6,
    hostgrp_hcdma6: HostgrpHcdma6,
    hostgrp_hcdmab6: HostgrpHcdmab6,
    _reserved94: [u8; 0x04],
    hostgrp_hcchar7: HostgrpHcchar7,
    hostgrp_hcsplt7: HostgrpHcsplt7,
    hostgrp_hcint7: HostgrpHcint7,
    hostgrp_hcintmsk7: HostgrpHcintmsk7,
    hostgrp_hctsiz7: HostgrpHctsiz7,
    hostgrp_hcdma7: HostgrpHcdma7,
    hostgrp_hcdmab7: HostgrpHcdmab7,
    _reserved101: [u8; 0x04],
    hostgrp_hcchar8: HostgrpHcchar8,
    hostgrp_hcsplt8: HostgrpHcsplt8,
    hostgrp_hcint8: HostgrpHcint8,
    hostgrp_hcintmsk8: HostgrpHcintmsk8,
    hostgrp_hctsiz8: HostgrpHctsiz8,
    hostgrp_hcdma8: HostgrpHcdma8,
    hostgrp_hcdmab8: HostgrpHcdmab8,
    _reserved108: [u8; 0x04],
    hostgrp_hcchar9: HostgrpHcchar9,
    hostgrp_hcsplt9: HostgrpHcsplt9,
    hostgrp_hcint9: HostgrpHcint9,
    hostgrp_hcintmsk9: HostgrpHcintmsk9,
    hostgrp_hctsiz9: HostgrpHctsiz9,
    hostgrp_hcdma9: HostgrpHcdma9,
    hostgrp_hcdmab9: HostgrpHcdmab9,
    _reserved115: [u8; 0x04],
    hostgrp_hcchar10: HostgrpHcchar10,
    hostgrp_hcsplt10: HostgrpHcsplt10,
    hostgrp_hcint10: HostgrpHcint10,
    hostgrp_hcintmsk10: HostgrpHcintmsk10,
    hostgrp_hctsiz10: HostgrpHctsiz10,
    hostgrp_hcdma10: HostgrpHcdma10,
    hostgrp_hcdmab10: HostgrpHcdmab10,
    _reserved122: [u8; 0x04],
    hostgrp_hcchar11: HostgrpHcchar11,
    hostgrp_hcsplt11: HostgrpHcsplt11,
    hostgrp_hcint11: HostgrpHcint11,
    hostgrp_hcintmsk11: HostgrpHcintmsk11,
    hostgrp_hctsiz11: HostgrpHctsiz11,
    hostgrp_hcdma11: HostgrpHcdma11,
    hostgrp_hcdmab11: HostgrpHcdmab11,
    _reserved129: [u8; 0x04],
    hostgrp_hcchar12: HostgrpHcchar12,
    hostgrp_hcsplt12: HostgrpHcsplt12,
    hostgrp_hcint12: HostgrpHcint12,
    hostgrp_hcintmsk12: HostgrpHcintmsk12,
    hostgrp_hctsiz12: HostgrpHctsiz12,
    hostgrp_hcdma12: HostgrpHcdma12,
    hostgrp_hcdmab12: HostgrpHcdmab12,
    _reserved136: [u8; 0x04],
    hostgrp_hcchar13: HostgrpHcchar13,
    hostgrp_hcsplt13: HostgrpHcsplt13,
    hostgrp_hcint13: HostgrpHcint13,
    hostgrp_hcintmsk13: HostgrpHcintmsk13,
    hostgrp_hctsiz13: HostgrpHctsiz13,
    hostgrp_hcdma13: HostgrpHcdma13,
    hostgrp_hcdmab13: HostgrpHcdmab13,
    _reserved143: [u8; 0x04],
    hostgrp_hcchar14: HostgrpHcchar14,
    hostgrp_hcsplt14: HostgrpHcsplt14,
    hostgrp_hcint14: HostgrpHcint14,
    hostgrp_hcintmsk14: HostgrpHcintmsk14,
    hostgrp_hctsiz14: HostgrpHctsiz14,
    hostgrp_hcdma14: HostgrpHcdma14,
    hostgrp_hcdmab14: HostgrpHcdmab14,
    _reserved150: [u8; 0x04],
    hostgrp_hcchar15: HostgrpHcchar15,
    hostgrp_hcsplt15: HostgrpHcsplt15,
    hostgrp_hcint15: HostgrpHcint15,
    hostgrp_hcintmsk15: HostgrpHcintmsk15,
    hostgrp_hctsiz15: HostgrpHctsiz15,
    hostgrp_hcdma15: HostgrpHcdma15,
    hostgrp_hcdmab15: HostgrpHcdmab15,
    _reserved157: [u8; 0x0104],
    devgrp_dcfg: DevgrpDcfg,
    devgrp_dctl: DevgrpDctl,
    devgrp_dsts: DevgrpDsts,
    _reserved160: [u8; 0x04],
    devgrp_diepmsk: DevgrpDiepmsk,
    devgrp_doepmsk: DevgrpDoepmsk,
    devgrp_daint: DevgrpDaint,
    devgrp_daintmsk: DevgrpDaintmsk,
    _reserved164: [u8; 0x08],
    devgrp_dvbusdis: DevgrpDvbusdis,
    devgrp_dvbuspulse: DevgrpDvbuspulse,
    devgrp_dthrctl: DevgrpDthrctl,
    devgrp_diepempmsk: DevgrpDiepempmsk,
    _reserved168: [u8; 0xc8],
    devgrp_diepctl0: DevgrpDiepctl0,
    _reserved169: [u8; 0x04],
    devgrp_diepint0: DevgrpDiepint0,
    _reserved170: [u8; 0x04],
    devgrp_dieptsiz0: DevgrpDieptsiz0,
    devgrp_diepdma0: DevgrpDiepdma0,
    devgrp_dtxfsts0: DevgrpDtxfsts0,
    devgrp_diepdmab0: DevgrpDiepdmab0,
    devgrp_diepctl1: DevgrpDiepctl1,
    _reserved175: [u8; 0x04],
    devgrp_diepint1: DevgrpDiepint1,
    _reserved176: [u8; 0x04],
    devgrp_dieptsiz1: DevgrpDieptsiz1,
    devgrp_diepdma1: DevgrpDiepdma1,
    devgrp_dtxfsts1: DevgrpDtxfsts1,
    devgrp_diepdmab1: DevgrpDiepdmab1,
    devgrp_diepctl2: DevgrpDiepctl2,
    _reserved181: [u8; 0x04],
    devgrp_diepint2: DevgrpDiepint2,
    _reserved182: [u8; 0x04],
    devgrp_dieptsiz2: DevgrpDieptsiz2,
    devgrp_diepdma2: DevgrpDiepdma2,
    devgrp_dtxfsts2: DevgrpDtxfsts2,
    devgrp_diepdmab2: DevgrpDiepdmab2,
    devgrp_diepctl3: DevgrpDiepctl3,
    _reserved187: [u8; 0x04],
    devgrp_diepint3: DevgrpDiepint3,
    _reserved188: [u8; 0x04],
    devgrp_dieptsiz3: DevgrpDieptsiz3,
    devgrp_diepdma3: DevgrpDiepdma3,
    devgrp_dtxfsts3: DevgrpDtxfsts3,
    devgrp_diepdmab3: DevgrpDiepdmab3,
    devgrp_diepctl4: DevgrpDiepctl4,
    _reserved193: [u8; 0x04],
    devgrp_diepint4: DevgrpDiepint4,
    _reserved194: [u8; 0x04],
    devgrp_dieptsiz4: DevgrpDieptsiz4,
    devgrp_diepdma4: DevgrpDiepdma4,
    devgrp_dtxfsts4: DevgrpDtxfsts4,
    devgrp_diepdmab4: DevgrpDiepdmab4,
    devgrp_diepctl5: DevgrpDiepctl5,
    _reserved199: [u8; 0x04],
    devgrp_diepint5: DevgrpDiepint5,
    _reserved200: [u8; 0x04],
    devgrp_dieptsiz5: DevgrpDieptsiz5,
    devgrp_diepdma5: DevgrpDiepdma5,
    devgrp_dtxfsts5: DevgrpDtxfsts5,
    devgrp_diepdmab5: DevgrpDiepdmab5,
    devgrp_diepctl6: DevgrpDiepctl6,
    _reserved205: [u8; 0x04],
    devgrp_diepint6: DevgrpDiepint6,
    _reserved206: [u8; 0x04],
    devgrp_dieptsiz6: DevgrpDieptsiz6,
    devgrp_diepdma6: DevgrpDiepdma6,
    devgrp_dtxfsts6: DevgrpDtxfsts6,
    devgrp_diepdmab6: DevgrpDiepdmab6,
    devgrp_diepctl7: DevgrpDiepctl7,
    _reserved211: [u8; 0x04],
    devgrp_diepint7: DevgrpDiepint7,
    _reserved212: [u8; 0x04],
    devgrp_dieptsiz7: DevgrpDieptsiz7,
    devgrp_diepdma7: DevgrpDiepdma7,
    devgrp_dtxfsts7: DevgrpDtxfsts7,
    devgrp_diepdmab7: DevgrpDiepdmab7,
    devgrp_diepctl8: DevgrpDiepctl8,
    _reserved217: [u8; 0x04],
    devgrp_diepint8: DevgrpDiepint8,
    _reserved218: [u8; 0x04],
    devgrp_dieptsiz8: DevgrpDieptsiz8,
    devgrp_diepdma8: DevgrpDiepdma8,
    devgrp_dtxfsts8: DevgrpDtxfsts8,
    devgrp_diepdmab8: DevgrpDiepdmab8,
    devgrp_diepctl9: DevgrpDiepctl9,
    _reserved223: [u8; 0x04],
    devgrp_diepint9: DevgrpDiepint9,
    _reserved224: [u8; 0x04],
    devgrp_dieptsiz9: DevgrpDieptsiz9,
    devgrp_diepdma9: DevgrpDiepdma9,
    devgrp_dtxfsts9: DevgrpDtxfsts9,
    devgrp_diepdmab9: DevgrpDiepdmab9,
    devgrp_diepctl10: DevgrpDiepctl10,
    _reserved229: [u8; 0x04],
    devgrp_diepint10: DevgrpDiepint10,
    _reserved230: [u8; 0x04],
    devgrp_dieptsiz10: DevgrpDieptsiz10,
    devgrp_diepdma10: DevgrpDiepdma10,
    devgrp_dtxfsts10: DevgrpDtxfsts10,
    devgrp_diepdmab10: DevgrpDiepdmab10,
    devgrp_diepctl11: DevgrpDiepctl11,
    _reserved235: [u8; 0x04],
    devgrp_diepint11: DevgrpDiepint11,
    _reserved236: [u8; 0x04],
    devgrp_dieptsiz11: DevgrpDieptsiz11,
    devgrp_diepdma11: DevgrpDiepdma11,
    devgrp_dtxfsts11: DevgrpDtxfsts11,
    devgrp_diepdmab11: DevgrpDiepdmab11,
    devgrp_diepctl12: DevgrpDiepctl12,
    _reserved241: [u8; 0x04],
    devgrp_diepint12: DevgrpDiepint12,
    _reserved242: [u8; 0x04],
    devgrp_dieptsiz12: DevgrpDieptsiz12,
    devgrp_diepdma12: DevgrpDiepdma12,
    devgrp_dtxfsts12: DevgrpDtxfsts12,
    devgrp_diepdmab12: DevgrpDiepdmab12,
    devgrp_diepctl13: DevgrpDiepctl13,
    _reserved247: [u8; 0x04],
    devgrp_diepint13: DevgrpDiepint13,
    _reserved248: [u8; 0x04],
    devgrp_dieptsiz13: DevgrpDieptsiz13,
    devgrp_diepdma13: DevgrpDiepdma13,
    devgrp_dtxfsts13: DevgrpDtxfsts13,
    devgrp_diepdmab13: DevgrpDiepdmab13,
    devgrp_diepctl14: DevgrpDiepctl14,
    _reserved253: [u8; 0x04],
    devgrp_diepint14: DevgrpDiepint14,
    _reserved254: [u8; 0x04],
    devgrp_dieptsiz14: DevgrpDieptsiz14,
    devgrp_diepdma14: DevgrpDiepdma14,
    devgrp_dtxfsts14: DevgrpDtxfsts14,
    devgrp_diepdmab14: DevgrpDiepdmab14,
    devgrp_diepctl15: DevgrpDiepctl15,
    _reserved259: [u8; 0x04],
    devgrp_diepint15: DevgrpDiepint15,
    _reserved260: [u8; 0x04],
    devgrp_dieptsiz15: DevgrpDieptsiz15,
    devgrp_diepdma15: DevgrpDiepdma15,
    devgrp_dtxfsts15: DevgrpDtxfsts15,
    devgrp_diepdmab15: DevgrpDiepdmab15,
    devgrp_doepctl0: DevgrpDoepctl0,
    _reserved265: [u8; 0x04],
    devgrp_doepint0: DevgrpDoepint0,
    _reserved266: [u8; 0x04],
    devgrp_doeptsiz0: DevgrpDoeptsiz0,
    devgrp_doepdma0: DevgrpDoepdma0,
    _reserved268: [u8; 0x04],
    devgrp_doepdmab0: DevgrpDoepdmab0,
    devgrp_doepctl1: DevgrpDoepctl1,
    _reserved270: [u8; 0x04],
    devgrp_doepint1: DevgrpDoepint1,
    _reserved271: [u8; 0x04],
    devgrp_doeptsiz1: DevgrpDoeptsiz1,
    devgrp_doepdma1: DevgrpDoepdma1,
    _reserved273: [u8; 0x04],
    devgrp_doepdmab1: DevgrpDoepdmab1,
    devgrp_doepctl2: DevgrpDoepctl2,
    _reserved275: [u8; 0x04],
    devgrp_doepint2: DevgrpDoepint2,
    _reserved276: [u8; 0x04],
    devgrp_doeptsiz2: DevgrpDoeptsiz2,
    devgrp_doepdma2: DevgrpDoepdma2,
    _reserved278: [u8; 0x04],
    devgrp_doepdmab2: DevgrpDoepdmab2,
    devgrp_doepctl3: DevgrpDoepctl3,
    _reserved280: [u8; 0x04],
    devgrp_doepint3: DevgrpDoepint3,
    _reserved281: [u8; 0x04],
    devgrp_doeptsiz3: DevgrpDoeptsiz3,
    devgrp_doepdma3: DevgrpDoepdma3,
    _reserved283: [u8; 0x04],
    devgrp_doepdmab3: DevgrpDoepdmab3,
    devgrp_doepctl4: DevgrpDoepctl4,
    _reserved285: [u8; 0x04],
    devgrp_doepint4: DevgrpDoepint4,
    _reserved286: [u8; 0x04],
    devgrp_doeptsiz4: DevgrpDoeptsiz4,
    devgrp_doepdma4: DevgrpDoepdma4,
    _reserved288: [u8; 0x04],
    devgrp_doepdmab4: DevgrpDoepdmab4,
    devgrp_doepctl5: DevgrpDoepctl5,
    _reserved290: [u8; 0x04],
    devgrp_doepint5: DevgrpDoepint5,
    _reserved291: [u8; 0x04],
    devgrp_doeptsiz5: DevgrpDoeptsiz5,
    devgrp_doepdma5: DevgrpDoepdma5,
    _reserved293: [u8; 0x04],
    devgrp_doepdmab5: DevgrpDoepdmab5,
    devgrp_doepctl6: DevgrpDoepctl6,
    _reserved295: [u8; 0x04],
    devgrp_doepint6: DevgrpDoepint6,
    _reserved296: [u8; 0x04],
    devgrp_doeptsiz6: DevgrpDoeptsiz6,
    devgrp_doepdma6: DevgrpDoepdma6,
    _reserved298: [u8; 0x04],
    devgrp_doepdmab6: DevgrpDoepdmab6,
    devgrp_doepctl7: DevgrpDoepctl7,
    _reserved300: [u8; 0x04],
    devgrp_doepint7: DevgrpDoepint7,
    _reserved301: [u8; 0x04],
    devgrp_doeptsiz7: DevgrpDoeptsiz7,
    devgrp_doepdma7: DevgrpDoepdma7,
    _reserved303: [u8; 0x04],
    devgrp_doepdmab7: DevgrpDoepdmab7,
    devgrp_doepctl8: DevgrpDoepctl8,
    _reserved305: [u8; 0x04],
    devgrp_doepint8: DevgrpDoepint8,
    _reserved306: [u8; 0x04],
    devgrp_doeptsiz8: DevgrpDoeptsiz8,
    devgrp_doepdma8: DevgrpDoepdma8,
    _reserved308: [u8; 0x04],
    devgrp_doepdmab8: DevgrpDoepdmab8,
    devgrp_doepctl9: DevgrpDoepctl9,
    _reserved310: [u8; 0x04],
    devgrp_doepint9: DevgrpDoepint9,
    _reserved311: [u8; 0x04],
    devgrp_doeptsiz9: DevgrpDoeptsiz9,
    devgrp_doepdma9: DevgrpDoepdma9,
    _reserved313: [u8; 0x04],
    devgrp_doepdmab9: DevgrpDoepdmab9,
    devgrp_doepctl10: DevgrpDoepctl10,
    _reserved315: [u8; 0x04],
    devgrp_doepint10: DevgrpDoepint10,
    _reserved316: [u8; 0x04],
    devgrp_doeptsiz10: DevgrpDoeptsiz10,
    devgrp_doepdma10: DevgrpDoepdma10,
    _reserved318: [u8; 0x04],
    devgrp_doepdmab10: DevgrpDoepdmab10,
    devgrp_doepctl11: DevgrpDoepctl11,
    _reserved320: [u8; 0x04],
    devgrp_doepint11: DevgrpDoepint11,
    _reserved321: [u8; 0x04],
    devgrp_doeptsiz11: DevgrpDoeptsiz11,
    devgrp_doepdma11: DevgrpDoepdma11,
    _reserved323: [u8; 0x04],
    devgrp_doepdmab11: DevgrpDoepdmab11,
    devgrp_doepctl12: DevgrpDoepctl12,
    _reserved325: [u8; 0x04],
    devgrp_doepint12: DevgrpDoepint12,
    _reserved326: [u8; 0x04],
    devgrp_doeptsiz12: DevgrpDoeptsiz12,
    devgrp_doepdma12: DevgrpDoepdma12,
    _reserved328: [u8; 0x04],
    devgrp_doepdmab12: DevgrpDoepdmab12,
    devgrp_doepctl13: DevgrpDoepctl13,
    _reserved330: [u8; 0x04],
    devgrp_doepint13: DevgrpDoepint13,
    _reserved331: [u8; 0x04],
    devgrp_doeptsiz13: DevgrpDoeptsiz13,
    devgrp_doepdma13: DevgrpDoepdma13,
    _reserved333: [u8; 0x04],
    devgrp_doepdmab13: DevgrpDoepdmab13,
    devgrp_doepctl14: DevgrpDoepctl14,
    _reserved335: [u8; 0x04],
    devgrp_doepint14: DevgrpDoepint14,
    _reserved336: [u8; 0x04],
    devgrp_doeptsiz14: DevgrpDoeptsiz14,
    devgrp_doepdma14: DevgrpDoepdma14,
    _reserved338: [u8; 0x04],
    devgrp_doepdmab14: DevgrpDoepdmab14,
    devgrp_doepctl15: DevgrpDoepctl15,
    _reserved340: [u8; 0x04],
    devgrp_doepint15: DevgrpDoepint15,
    _reserved341: [u8; 0x04],
    devgrp_doeptsiz15: DevgrpDoeptsiz15,
    devgrp_doepdma15: DevgrpDoepdma15,
    _reserved343: [u8; 0x04],
    devgrp_doepdmab15: DevgrpDoepdmab15,
    _reserved344: [u8; 0x0100],
    pwrclkgrp_pcgcctl: PwrclkgrpPcgcctl,
}
impl crate::FromBytes for RegisterBlock {}
impl RegisterBlock {
    #[doc = "0x00 - The OTG Control and Status register controls the behavior and reflects the status of the OTG function."]
    #[inline(always)]
    pub const fn globgrp_gotgctl(&self) -> &GlobgrpGotgctl {
        &self.globgrp_gotgctl
    }
    #[doc = "0x04 - The application reads this register whenever there is an OTG interrupt and clears the bits in this register to clear the OTG interrupt."]
    #[inline(always)]
    pub const fn globgrp_gotgint(&self) -> &GlobgrpGotgint {
        &self.globgrp_gotgint
    }
    #[doc = "0x08 - This register can be used to configure the core after power-on or a change in mode. This register mainly contains AHB system-related configuration parameters. Do not change this register after the initial programming. The application must program this register before starting any transactions on either the AHB or the USB."]
    #[inline(always)]
    pub const fn globgrp_gahbcfg(&self) -> &GlobgrpGahbcfg {
        &self.globgrp_gahbcfg
    }
    #[doc = "0x0c - This register can be used to configure the core after power-on or a changing to Host mode or Device mode. It contains USB and USB-PHY related configuration parameters. The application must program this register before starting any transactions on either the AHB or the USB. Do not make changes to this register after the initial programming."]
    #[inline(always)]
    pub const fn globgrp_gusbcfg(&self) -> &GlobgrpGusbcfg {
        &self.globgrp_gusbcfg
    }
    #[doc = "0x10 - The application uses this register to reset various hardware features inside the core"]
    #[inline(always)]
    pub const fn globgrp_grstctl(&self) -> &GlobgrpGrstctl {
        &self.globgrp_grstctl
    }
    #[doc = "0x14 - This register interrupts the application for system-level events in the current mode (Device mode or Host mode). Some of the bits in this register are valid only in Host mode, while others are valid in Device mode only. This register also indicates the current mode. To clear the interrupt status bits of type R_SS_WC, the application must write 1 into the bit. The FIFO status interrupts are read only; once software reads from or writes to the FIFO while servicing these interrupts, FIFO interrupt conditions are cleared automatically. The application must clear the GINTSTS register at initialization before unmasking the interrupt bit to avoid any interrupts generated prior to initialization."]
    #[inline(always)]
    pub const fn globgrp_gintsts(&self) -> &GlobgrpGintsts {
        &self.globgrp_gintsts
    }
    #[doc = "0x18 - This register works with the Interrupt Register (GINTSTS) to interrupt the application. When an interrupt bit is masked, the interrupt associated with that bit is not generated. However, the GINTSTS register bit corresponding to that interrupt is still set."]
    #[inline(always)]
    pub const fn globgrp_gintmsk(&self) -> &GlobgrpGintmsk {
        &self.globgrp_gintmsk
    }
    #[doc = "0x1c - A read to the Receive Status Read and Pop register additionally pops the: top data entry out of the RxFIFO. The receive status contents must be interpreted differently in Host and Device modes. The core ignores the receive status pop/read when the receive FIFO is empty and returns a value of 0. The application must only pop the Receive Status FIFO when the Receive FIFO Non-Empty bit of the Core Interrupt register (GINTSTS.RxFLvl) is asserted. Use of these fields vary based on whether the HS OTG core is functioning as a host or a device. Do not read this register's reset value before configuring the core because the read value is \"X\" in the simulation."]
    #[inline(always)]
    pub const fn globgrp_grxstsr(&self) -> &GlobgrpGrxstsr {
        &self.globgrp_grxstsr
    }
    #[doc = "0x20 - A read to the Receive Status Read and Pop register additionally pops the: top data entry out of the RxFIFO. The receive status contents must be interpreted differently in Host and Device modes. The core ignores the receive status pop/read when the receive FIFO is empty and returns a value of 0. The application must only pop the Receive Status FIFO when the Receive FIFO Non-Empty bit of the Core Interrupt register (GINTSTS.RxFLvl) is asserted. Use of these fields vary based on whether the HS OTG core is functioning as a host or a device. Do not read this register'ss reset value before configuring the core because the read value is \"X\" in the simulation."]
    #[inline(always)]
    pub const fn globgrp_grxstsp(&self) -> &GlobgrpGrxstsp {
        &self.globgrp_grxstsp
    }
    #[doc = "0x24 - The application can program the RAM size that must be allocated to the RxFIFO."]
    #[inline(always)]
    pub const fn globgrp_grxfsiz(&self) -> &GlobgrpGrxfsiz {
        &self.globgrp_grxfsiz
    }
    #[doc = "0x28 - The application can program the RAM size and the memory start address for the Non-periodic TxFIFO. The fields of this register change, depending on host or device mode."]
    #[inline(always)]
    pub const fn globgrp_gnptxfsiz(&self) -> &GlobgrpGnptxfsiz {
        &self.globgrp_gnptxfsiz
    }
    #[doc = "0x2c - In Device mode, this register is valid only in Shared FIFO operation. It contains the free space information for the Non-periodic TxFIFO and the Nonperiodic Transmit RequestQueue"]
    #[inline(always)]
    pub const fn globgrp_gnptxsts(&self) -> &GlobgrpGnptxsts {
        &self.globgrp_gnptxsts
    }
    #[doc = "0x34 - The application can use this register to access PHY registers. for a ULPI PHY, the core uses the ULPI interface for PHY register access. The application sets Vendor Control register for PHY register access and times the PHY register access. The application polls the VStatus Done bit in this register for the completion of the PHY register access"]
    #[inline(always)]
    pub const fn globgrp_gpvndctl(&self) -> &GlobgrpGpvndctl {
        &self.globgrp_gpvndctl
    }
    #[doc = "0x38 - The application can use this register for general purpose input/output ports or for debugging."]
    #[inline(always)]
    pub const fn globgrp_ggpio(&self) -> &GlobgrpGgpio {
        &self.globgrp_ggpio
    }
    #[doc = "0x3c - This is a read/write register containing the User ID. This register can be used in the following ways: -To store the version or revision of your system -To store hardware configurations that are outside the otg core As a scratch register"]
    #[inline(always)]
    pub const fn globgrp_guid(&self) -> &GlobgrpGuid {
        &self.globgrp_guid
    }
    #[doc = "0x40 - This read-only register contains the release number of the core being used."]
    #[inline(always)]
    pub const fn globgrp_gsnpsid(&self) -> &GlobgrpGsnpsid {
        &self.globgrp_gsnpsid
    }
    #[doc = "0x44 - This register contains the logical endpoint direction(s)."]
    #[inline(always)]
    pub const fn globgrp_ghwcfg1(&self) -> &GlobgrpGhwcfg1 {
        &self.globgrp_ghwcfg1
    }
    #[doc = "0x48 - This register contains configuration options."]
    #[inline(always)]
    pub const fn globgrp_ghwcfg2(&self) -> &GlobgrpGhwcfg2 {
        &self.globgrp_ghwcfg2
    }
    #[doc = "0x4c - This register contains the configuration options."]
    #[inline(always)]
    pub const fn globgrp_ghwcfg3(&self) -> &GlobgrpGhwcfg3 {
        &self.globgrp_ghwcfg3
    }
    #[doc = "0x50 - This register contains the configuration options."]
    #[inline(always)]
    pub const fn globgrp_ghwcfg4(&self) -> &GlobgrpGhwcfg4 {
        &self.globgrp_ghwcfg4
    }
    #[doc = "0x5c - Specifies whether Dedicated Transmit FIFOs should be enabled in device mode."]
    #[inline(always)]
    pub const fn globgrp_gdfifocfg(&self) -> &GlobgrpGdfifocfg {
        &self.globgrp_gdfifocfg
    }
    #[doc = "0x100 - This register holds the size and the memory start address of the Periodic TxFIFO"]
    #[inline(always)]
    pub const fn globgrp_hptxfsiz(&self) -> &GlobgrpHptxfsiz {
        &self.globgrp_hptxfsiz
    }
    #[doc = "0x104 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf1(&self) -> &GlobgrpDieptxf1 {
        &self.globgrp_dieptxf1
    }
    #[doc = "0x108 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf2(&self) -> &GlobgrpDieptxf2 {
        &self.globgrp_dieptxf2
    }
    #[doc = "0x10c - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf3(&self) -> &GlobgrpDieptxf3 {
        &self.globgrp_dieptxf3
    }
    #[doc = "0x110 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf4(&self) -> &GlobgrpDieptxf4 {
        &self.globgrp_dieptxf4
    }
    #[doc = "0x114 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf5(&self) -> &GlobgrpDieptxf5 {
        &self.globgrp_dieptxf5
    }
    #[doc = "0x118 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf6(&self) -> &GlobgrpDieptxf6 {
        &self.globgrp_dieptxf6
    }
    #[doc = "0x11c - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf7(&self) -> &GlobgrpDieptxf7 {
        &self.globgrp_dieptxf7
    }
    #[doc = "0x120 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf8(&self) -> &GlobgrpDieptxf8 {
        &self.globgrp_dieptxf8
    }
    #[doc = "0x124 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf9(&self) -> &GlobgrpDieptxf9 {
        &self.globgrp_dieptxf9
    }
    #[doc = "0x128 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf10(&self) -> &GlobgrpDieptxf10 {
        &self.globgrp_dieptxf10
    }
    #[doc = "0x12c - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf11(&self) -> &GlobgrpDieptxf11 {
        &self.globgrp_dieptxf11
    }
    #[doc = "0x130 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf12(&self) -> &GlobgrpDieptxf12 {
        &self.globgrp_dieptxf12
    }
    #[doc = "0x134 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf13(&self) -> &GlobgrpDieptxf13 {
        &self.globgrp_dieptxf13
    }
    #[doc = "0x138 - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf14(&self) -> &GlobgrpDieptxf14 {
        &self.globgrp_dieptxf14
    }
    #[doc = "0x13c - This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
    #[inline(always)]
    pub const fn globgrp_dieptxf15(&self) -> &GlobgrpDieptxf15 {
        &self.globgrp_dieptxf15
    }
    #[doc = "0x400 - Host Mode control. This register must be programmed every time the core changes to Host mode"]
    #[inline(always)]
    pub const fn hostgrp_hcfg(&self) -> &HostgrpHcfg {
        &self.hostgrp_hcfg
    }
    #[doc = "0x404 - This register stores the frame interval information for the current speed to which the otg core has enumerated"]
    #[inline(always)]
    pub const fn hostgrp_hfir(&self) -> &HostgrpHfir {
        &self.hostgrp_hfir
    }
    #[doc = "0x408 - This register contains the free space information for the Periodic TxFIFO and the Periodic Transmit Request Queue"]
    #[inline(always)]
    pub const fn hostgrp_hfnum(&self) -> &HostgrpHfnum {
        &self.hostgrp_hfnum
    }
    #[doc = "0x410 - This register contains the free space information for the Periodic TxFIFO and the Periodic Transmit Request Queue."]
    #[inline(always)]
    pub const fn hostgrp_hptxsts(&self) -> &HostgrpHptxsts {
        &self.hostgrp_hptxsts
    }
    #[doc = "0x414 - When a significant event occurs on a channel, the Host All Channels Interrupt register interrupts the application using the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt). There is one interrupt bit per channel, up to a maximum of 16 bits. Bits in this register are set and cleared when the application sets and clears bits in the corresponding Host Channel-n Interrupt register."]
    #[inline(always)]
    pub const fn hostgrp_haint(&self) -> &HostgrpHaint {
        &self.hostgrp_haint
    }
    #[doc = "0x418 - The Host All Channel Interrupt Mask register works with the Host All Channel Interrupt register to interrupt the application when an event occurs on a channel. There is one interrupt mask bit per channel, up to a maximum of 16 bits."]
    #[inline(always)]
    pub const fn hostgrp_haintmsk(&self) -> &HostgrpHaintmsk {
        &self.hostgrp_haintmsk
    }
    #[doc = "0x41c - This Register is valid only for Host mode Scatter-Gather DMA. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
    #[inline(always)]
    pub const fn hostgrp_hflbaddr(&self) -> &HostgrpHflbaddr {
        &self.hostgrp_hflbaddr
    }
    #[doc = "0x440 - This register is available only in Host mode. Currently, the OTG Host supports only one port. A single register holds USB port-related information such as USB reset, enable, suspend, resume, connect status, and test mode for each port.The R_SS_WC bits in this register can trigger an interrupt to the application through the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). On a Port Interrupt, the application must read this register and clear the bit that caused the interrupt. for the R_SS_WC bits, the application must write a 1 to the bit to clear the interrupt"]
    #[inline(always)]
    pub const fn hostgrp_hprt(&self) -> &HostgrpHprt {
        &self.hostgrp_hprt
    }
    #[doc = "0x500 - Channel_number: 0."]
    #[inline(always)]
    pub const fn hostgrp_hcchar0(&self) -> &HostgrpHcchar0 {
        &self.hostgrp_hcchar0
    }
    #[doc = "0x504 - Channel_number 0"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt0(&self) -> &HostgrpHcsplt0 {
        &self.hostgrp_hcsplt0
    }
    #[doc = "0x508 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint0(&self) -> &HostgrpHcint0 {
        &self.hostgrp_hcint0
    }
    #[doc = "0x50c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk0(&self) -> &HostgrpHcintmsk0 {
        &self.hostgrp_hcintmsk0
    }
    #[doc = "0x510 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz0(&self) -> &HostgrpHctsiz0 {
        &self.hostgrp_hctsiz0
    }
    #[doc = "0x514 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma0(&self) -> &HostgrpHcdma0 {
        &self.hostgrp_hcdma0
    }
    #[doc = "0x518 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab0(&self) -> &HostgrpHcdmab0 {
        &self.hostgrp_hcdmab0
    }
    #[doc = "0x520 - Host Channel 1 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar1(&self) -> &HostgrpHcchar1 {
        &self.hostgrp_hcchar1
    }
    #[doc = "0x524 - Channel_number 1"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt1(&self) -> &HostgrpHcsplt1 {
        &self.hostgrp_hcsplt1
    }
    #[doc = "0x528 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint1(&self) -> &HostgrpHcint1 {
        &self.hostgrp_hcint1
    }
    #[doc = "0x52c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk1(&self) -> &HostgrpHcintmsk1 {
        &self.hostgrp_hcintmsk1
    }
    #[doc = "0x530 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz1(&self) -> &HostgrpHctsiz1 {
        &self.hostgrp_hctsiz1
    }
    #[doc = "0x534 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma1(&self) -> &HostgrpHcdma1 {
        &self.hostgrp_hcdma1
    }
    #[doc = "0x538 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab1(&self) -> &HostgrpHcdmab1 {
        &self.hostgrp_hcdmab1
    }
    #[doc = "0x540 - Host Channel 2 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar2(&self) -> &HostgrpHcchar2 {
        &self.hostgrp_hcchar2
    }
    #[doc = "0x544 - Channel_number 2"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt2(&self) -> &HostgrpHcsplt2 {
        &self.hostgrp_hcsplt2
    }
    #[doc = "0x548 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint2(&self) -> &HostgrpHcint2 {
        &self.hostgrp_hcint2
    }
    #[doc = "0x54c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk2(&self) -> &HostgrpHcintmsk2 {
        &self.hostgrp_hcintmsk2
    }
    #[doc = "0x550 - Buffer DMA Mode."]
    #[inline(always)]
    pub const fn hostgrp_hctsiz2(&self) -> &HostgrpHctsiz2 {
        &self.hostgrp_hctsiz2
    }
    #[doc = "0x554 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma2(&self) -> &HostgrpHcdma2 {
        &self.hostgrp_hcdma2
    }
    #[doc = "0x558 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab2(&self) -> &HostgrpHcdmab2 {
        &self.hostgrp_hcdmab2
    }
    #[doc = "0x560 - Channel_number: 3."]
    #[inline(always)]
    pub const fn hostgrp_hcchar3(&self) -> &HostgrpHcchar3 {
        &self.hostgrp_hcchar3
    }
    #[doc = "0x564 - Channel_number 3"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt3(&self) -> &HostgrpHcsplt3 {
        &self.hostgrp_hcsplt3
    }
    #[doc = "0x568 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint3(&self) -> &HostgrpHcint3 {
        &self.hostgrp_hcint3
    }
    #[doc = "0x56c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk3(&self) -> &HostgrpHcintmsk3 {
        &self.hostgrp_hcintmsk3
    }
    #[doc = "0x570 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz3(&self) -> &HostgrpHctsiz3 {
        &self.hostgrp_hctsiz3
    }
    #[doc = "0x574 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma3(&self) -> &HostgrpHcdma3 {
        &self.hostgrp_hcdma3
    }
    #[doc = "0x578 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab3(&self) -> &HostgrpHcdmab3 {
        &self.hostgrp_hcdmab3
    }
    #[doc = "0x580 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcchar4(&self) -> &HostgrpHcchar4 {
        &self.hostgrp_hcchar4
    }
    #[doc = "0x584 - Channel_number 4"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt4(&self) -> &HostgrpHcsplt4 {
        &self.hostgrp_hcsplt4
    }
    #[doc = "0x588 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint4(&self) -> &HostgrpHcint4 {
        &self.hostgrp_hcint4
    }
    #[doc = "0x58c - This register reflects the mask for Channel 4 interrupt status bits."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk4(&self) -> &HostgrpHcintmsk4 {
        &self.hostgrp_hcintmsk4
    }
    #[doc = "0x590 - Buffer DMA Mode Channel 4"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz4(&self) -> &HostgrpHctsiz4 {
        &self.hostgrp_hctsiz4
    }
    #[doc = "0x594 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma4(&self) -> &HostgrpHcdma4 {
        &self.hostgrp_hcdma4
    }
    #[doc = "0x598 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab4(&self) -> &HostgrpHcdmab4 {
        &self.hostgrp_hcdmab4
    }
    #[doc = "0x5a0 - Channel_number: 5."]
    #[inline(always)]
    pub const fn hostgrp_hcchar5(&self) -> &HostgrpHcchar5 {
        &self.hostgrp_hcchar5
    }
    #[doc = "0x5a4 - Channel_number 5"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt5(&self) -> &HostgrpHcsplt5 {
        &self.hostgrp_hcsplt5
    }
    #[doc = "0x5a8 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint5(&self) -> &HostgrpHcint5 {
        &self.hostgrp_hcint5
    }
    #[doc = "0x5ac - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk5(&self) -> &HostgrpHcintmsk5 {
        &self.hostgrp_hcintmsk5
    }
    #[doc = "0x5b0 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz5(&self) -> &HostgrpHctsiz5 {
        &self.hostgrp_hctsiz5
    }
    #[doc = "0x5b4 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma5(&self) -> &HostgrpHcdma5 {
        &self.hostgrp_hcdma5
    }
    #[doc = "0x5b8 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab5(&self) -> &HostgrpHcdmab5 {
        &self.hostgrp_hcdmab5
    }
    #[doc = "0x5c0 - Host Channel 6 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar6(&self) -> &HostgrpHcchar6 {
        &self.hostgrp_hcchar6
    }
    #[doc = "0x5c4 - Channel_number 6"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt6(&self) -> &HostgrpHcsplt6 {
        &self.hostgrp_hcsplt6
    }
    #[doc = "0x5c8 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint6(&self) -> &HostgrpHcint6 {
        &self.hostgrp_hcint6
    }
    #[doc = "0x5cc - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk6(&self) -> &HostgrpHcintmsk6 {
        &self.hostgrp_hcintmsk6
    }
    #[doc = "0x5d0 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz6(&self) -> &HostgrpHctsiz6 {
        &self.hostgrp_hctsiz6
    }
    #[doc = "0x5d4 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma6(&self) -> &HostgrpHcdma6 {
        &self.hostgrp_hcdma6
    }
    #[doc = "0x5d8 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab6(&self) -> &HostgrpHcdmab6 {
        &self.hostgrp_hcdmab6
    }
    #[doc = "0x5e0 - Host Channel 7 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar7(&self) -> &HostgrpHcchar7 {
        &self.hostgrp_hcchar7
    }
    #[doc = "0x5e4 - Channel_number 7"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt7(&self) -> &HostgrpHcsplt7 {
        &self.hostgrp_hcsplt7
    }
    #[doc = "0x5e8 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint7(&self) -> &HostgrpHcint7 {
        &self.hostgrp_hcint7
    }
    #[doc = "0x5ec - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk7(&self) -> &HostgrpHcintmsk7 {
        &self.hostgrp_hcintmsk7
    }
    #[doc = "0x5f0 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz7(&self) -> &HostgrpHctsiz7 {
        &self.hostgrp_hctsiz7
    }
    #[doc = "0x5f4 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma7(&self) -> &HostgrpHcdma7 {
        &self.hostgrp_hcdma7
    }
    #[doc = "0x5f8 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab7(&self) -> &HostgrpHcdmab7 {
        &self.hostgrp_hcdmab7
    }
    #[doc = "0x600 - Host Channel 8 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar8(&self) -> &HostgrpHcchar8 {
        &self.hostgrp_hcchar8
    }
    #[doc = "0x604 - Channel_number 8"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt8(&self) -> &HostgrpHcsplt8 {
        &self.hostgrp_hcsplt8
    }
    #[doc = "0x608 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint8(&self) -> &HostgrpHcint8 {
        &self.hostgrp_hcint8
    }
    #[doc = "0x60c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk8(&self) -> &HostgrpHcintmsk8 {
        &self.hostgrp_hcintmsk8
    }
    #[doc = "0x610 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz8(&self) -> &HostgrpHctsiz8 {
        &self.hostgrp_hctsiz8
    }
    #[doc = "0x614 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma8(&self) -> &HostgrpHcdma8 {
        &self.hostgrp_hcdma8
    }
    #[doc = "0x618 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab8(&self) -> &HostgrpHcdmab8 {
        &self.hostgrp_hcdmab8
    }
    #[doc = "0x620 - Host Channel 9 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar9(&self) -> &HostgrpHcchar9 {
        &self.hostgrp_hcchar9
    }
    #[doc = "0x624 - Channel_number 9"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt9(&self) -> &HostgrpHcsplt9 {
        &self.hostgrp_hcsplt9
    }
    #[doc = "0x628 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint9(&self) -> &HostgrpHcint9 {
        &self.hostgrp_hcint9
    }
    #[doc = "0x62c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk9(&self) -> &HostgrpHcintmsk9 {
        &self.hostgrp_hcintmsk9
    }
    #[doc = "0x630 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz9(&self) -> &HostgrpHctsiz9 {
        &self.hostgrp_hctsiz9
    }
    #[doc = "0x634 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma9(&self) -> &HostgrpHcdma9 {
        &self.hostgrp_hcdma9
    }
    #[doc = "0x638 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab9(&self) -> &HostgrpHcdmab9 {
        &self.hostgrp_hcdmab9
    }
    #[doc = "0x640 - Host Channel 1 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar10(&self) -> &HostgrpHcchar10 {
        &self.hostgrp_hcchar10
    }
    #[doc = "0x644 - Channel_number 1"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt10(&self) -> &HostgrpHcsplt10 {
        &self.hostgrp_hcsplt10
    }
    #[doc = "0x648 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint10(&self) -> &HostgrpHcint10 {
        &self.hostgrp_hcint10
    }
    #[doc = "0x64c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk10(&self) -> &HostgrpHcintmsk10 {
        &self.hostgrp_hcintmsk10
    }
    #[doc = "0x650 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz10(&self) -> &HostgrpHctsiz10 {
        &self.hostgrp_hctsiz10
    }
    #[doc = "0x654 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma10(&self) -> &HostgrpHcdma10 {
        &self.hostgrp_hcdma10
    }
    #[doc = "0x658 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab10(&self) -> &HostgrpHcdmab10 {
        &self.hostgrp_hcdmab10
    }
    #[doc = "0x660 - Host Channel 11 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar11(&self) -> &HostgrpHcchar11 {
        &self.hostgrp_hcchar11
    }
    #[doc = "0x664 - Channel number 11."]
    #[inline(always)]
    pub const fn hostgrp_hcsplt11(&self) -> &HostgrpHcsplt11 {
        &self.hostgrp_hcsplt11
    }
    #[doc = "0x668 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint11(&self) -> &HostgrpHcint11 {
        &self.hostgrp_hcint11
    }
    #[doc = "0x66c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk11(&self) -> &HostgrpHcintmsk11 {
        &self.hostgrp_hcintmsk11
    }
    #[doc = "0x670 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz11(&self) -> &HostgrpHctsiz11 {
        &self.hostgrp_hctsiz11
    }
    #[doc = "0x674 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma11(&self) -> &HostgrpHcdma11 {
        &self.hostgrp_hcdma11
    }
    #[doc = "0x678 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab11(&self) -> &HostgrpHcdmab11 {
        &self.hostgrp_hcdmab11
    }
    #[doc = "0x680 - Host Channel 1 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar12(&self) -> &HostgrpHcchar12 {
        &self.hostgrp_hcchar12
    }
    #[doc = "0x684 - Channel_number 1"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt12(&self) -> &HostgrpHcsplt12 {
        &self.hostgrp_hcsplt12
    }
    #[doc = "0x688 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint12(&self) -> &HostgrpHcint12 {
        &self.hostgrp_hcint12
    }
    #[doc = "0x68c - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk12(&self) -> &HostgrpHcintmsk12 {
        &self.hostgrp_hcintmsk12
    }
    #[doc = "0x690 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz12(&self) -> &HostgrpHctsiz12 {
        &self.hostgrp_hctsiz12
    }
    #[doc = "0x694 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma12(&self) -> &HostgrpHcdma12 {
        &self.hostgrp_hcdma12
    }
    #[doc = "0x698 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab12(&self) -> &HostgrpHcdmab12 {
        &self.hostgrp_hcdmab12
    }
    #[doc = "0x6a0 - Host Channel 13 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar13(&self) -> &HostgrpHcchar13 {
        &self.hostgrp_hcchar13
    }
    #[doc = "0x6a4 - Channel_number 13."]
    #[inline(always)]
    pub const fn hostgrp_hcsplt13(&self) -> &HostgrpHcsplt13 {
        &self.hostgrp_hcsplt13
    }
    #[doc = "0x6a8 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint13(&self) -> &HostgrpHcint13 {
        &self.hostgrp_hcint13
    }
    #[doc = "0x6ac - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk13(&self) -> &HostgrpHcintmsk13 {
        &self.hostgrp_hcintmsk13
    }
    #[doc = "0x6b0 - Buffer DMA Mode"]
    #[inline(always)]
    pub const fn hostgrp_hctsiz13(&self) -> &HostgrpHctsiz13 {
        &self.hostgrp_hctsiz13
    }
    #[doc = "0x6b4 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma13(&self) -> &HostgrpHcdma13 {
        &self.hostgrp_hcdma13
    }
    #[doc = "0x6b8 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab13(&self) -> &HostgrpHcdmab13 {
        &self.hostgrp_hcdmab13
    }
    #[doc = "0x6c0 - Host Channel 1 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar14(&self) -> &HostgrpHcchar14 {
        &self.hostgrp_hcchar14
    }
    #[doc = "0x6c4 - Channel_number 14"]
    #[inline(always)]
    pub const fn hostgrp_hcsplt14(&self) -> &HostgrpHcsplt14 {
        &self.hostgrp_hcsplt14
    }
    #[doc = "0x6c8 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint14(&self) -> &HostgrpHcint14 {
        &self.hostgrp_hcint14
    }
    #[doc = "0x6cc - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk14(&self) -> &HostgrpHcintmsk14 {
        &self.hostgrp_hcintmsk14
    }
    #[doc = "0x6d0 - "]
    #[inline(always)]
    pub const fn hostgrp_hctsiz14(&self) -> &HostgrpHctsiz14 {
        &self.hostgrp_hctsiz14
    }
    #[doc = "0x6d4 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma14(&self) -> &HostgrpHcdma14 {
        &self.hostgrp_hcdma14
    }
    #[doc = "0x6d8 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab14(&self) -> &HostgrpHcdmab14 {
        &self.hostgrp_hcdmab14
    }
    #[doc = "0x6e0 - Host Channel 15 Characteristics Register"]
    #[inline(always)]
    pub const fn hostgrp_hcchar15(&self) -> &HostgrpHcchar15 {
        &self.hostgrp_hcchar15
    }
    #[doc = "0x6e4 - Channel_number 15."]
    #[inline(always)]
    pub const fn hostgrp_hcsplt15(&self) -> &HostgrpHcsplt15 {
        &self.hostgrp_hcsplt15
    }
    #[doc = "0x6e8 - This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn hostgrp_hcint15(&self) -> &HostgrpHcint15 {
        &self.hostgrp_hcint15
    }
    #[doc = "0x6ec - This register reflects the mask for each channel status described in the previous section."]
    #[inline(always)]
    pub const fn hostgrp_hcintmsk15(&self) -> &HostgrpHcintmsk15 {
        &self.hostgrp_hcintmsk15
    }
    #[doc = "0x6f0 - "]
    #[inline(always)]
    pub const fn hostgrp_hctsiz15(&self) -> &HostgrpHctsiz15 {
        &self.hostgrp_hctsiz15
    }
    #[doc = "0x6f4 - This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
    #[inline(always)]
    pub const fn hostgrp_hcdma15(&self) -> &HostgrpHcdma15 {
        &self.hostgrp_hcdma15
    }
    #[doc = "0x6f8 - These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
    #[inline(always)]
    pub const fn hostgrp_hcdmab15(&self) -> &HostgrpHcdmab15 {
        &self.hostgrp_hcdmab15
    }
    #[doc = "0x800 - This register configures the core in Device mode after power-on or after certain control commands or enumeration. Do not make changes to this register after initial programming."]
    #[inline(always)]
    pub const fn devgrp_dcfg(&self) -> &DevgrpDcfg {
        &self.devgrp_dcfg
    }
    #[doc = "0x804 - "]
    #[inline(always)]
    pub const fn devgrp_dctl(&self) -> &DevgrpDctl {
        &self.devgrp_dctl
    }
    #[doc = "0x808 - This register indicates the status of the core with respect to USB-related events. It must be read on interrupts from Device All Interrupts (DAINT) register."]
    #[inline(always)]
    pub const fn devgrp_dsts(&self) -> &DevgrpDsts {
        &self.devgrp_dsts
    }
    #[doc = "0x810 - This register works with each of the Device IN Endpoint Interrupt (DIEPINTn) registers for all endpoints to generate an interrupt per IN endpoint. The IN endpoint interrupt for a specific status in the DIEPINTn register can be masked by writing to the corresponding bit in this register. Status bits are masked by default."]
    #[inline(always)]
    pub const fn devgrp_diepmsk(&self) -> &DevgrpDiepmsk {
        &self.devgrp_diepmsk
    }
    #[doc = "0x814 - This register works with each of the Device OUT Endpoint Interrupt (DOEPINTn) registers for all endpoints to generate an interrupt per OUT endpoint. The OUT endpoint interrupt for a specific status in the DOEPINTn register can be masked by writing into the corresponding bit in this register. Status bits are masked by default"]
    #[inline(always)]
    pub const fn devgrp_doepmsk(&self) -> &DevgrpDoepmsk {
        &self.devgrp_doepmsk
    }
    #[doc = "0x818 - When a significant event occurs on an endpoint, a Device All Endpoints Interrupt register interrupts the application using the Device OUT Endpoints Interrupt bit or Device IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively). This is shown in Figure 5-2. There is one interrupt bit per endpoint, up to a maximum of 16 bits for OUT endpoints and 16 bits for IN endpoints. for a bidirectional endpoint, the corresponding IN and OUT interrupt bits are used. Bits in this register are set and cleared when the application sets and clears bits in the corresponding Device Endpoint-n Interrupt register (DIEPINTn/DOEPINTn)."]
    #[inline(always)]
    pub const fn devgrp_daint(&self) -> &DevgrpDaint {
        &self.devgrp_daint
    }
    #[doc = "0x81c - The Device Endpoint Interrupt Mask register works with the Device Endpoint Interrupt register to interrupt the application when an event occurs on a device endpoint. However, the Device All Endpoints Interrupt (DAINT) register bit corresponding to that interrupt is still set."]
    #[inline(always)]
    pub const fn devgrp_daintmsk(&self) -> &DevgrpDaintmsk {
        &self.devgrp_daintmsk
    }
    #[doc = "0x828 - This register specifies the VBUS discharge time after VBUS pulsing during SRP."]
    #[inline(always)]
    pub const fn devgrp_dvbusdis(&self) -> &DevgrpDvbusdis {
        &self.devgrp_dvbusdis
    }
    #[doc = "0x82c - This register specifies the VBUS pulsing time during SRP."]
    #[inline(always)]
    pub const fn devgrp_dvbuspulse(&self) -> &DevgrpDvbuspulse {
        &self.devgrp_dvbuspulse
    }
    #[doc = "0x830 - Thresholding is not supported in Slave mode and so this register must not be programmed in Slave mode. for threshold support, the AHB must be run at 60 MHz or higher."]
    #[inline(always)]
    pub const fn devgrp_dthrctl(&self) -> &DevgrpDthrctl {
        &self.devgrp_dthrctl
    }
    #[doc = "0x834 - This register is used to control the IN endpoint FIFO empty interrupt generation (DIEPINTn.TxfEmp)."]
    #[inline(always)]
    pub const fn devgrp_diepempmsk(&self) -> &DevgrpDiepempmsk {
        &self.devgrp_diepempmsk
    }
    #[doc = "0x900 - This register covers Device Control IN Endpoint 0."]
    #[inline(always)]
    pub const fn devgrp_diepctl0(&self) -> &DevgrpDiepctl0 {
        &self.devgrp_diepctl0
    }
    #[doc = "0x908 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint0(&self) -> &DevgrpDiepint0 {
        &self.devgrp_diepint0
    }
    #[doc = "0x910 - The application must modify this register before enabling endpoint 0. Once endpoint 0 is enabled using Endpoint Enable bit of the Device Control Endpoint 0 Control registers (DIEPCTL0.EPEna/DOEPCTL0.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit. Nonzero endpoints use the registers for endpoints 1 to 15. When Scatter/Gather DMA mode is enabled, this register must not be programmed by the application. If the application reads this register when Scatter/Gather DMA mode is enabled, the core returns all zeros."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz0(&self) -> &DevgrpDieptsiz0 {
        &self.devgrp_dieptsiz0
    }
    #[doc = "0x914 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma0(&self) -> &DevgrpDiepdma0 {
        &self.devgrp_diepdma0
    }
    #[doc = "0x918 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts0(&self) -> &DevgrpDtxfsts0 {
        &self.devgrp_dtxfsts0
    }
    #[doc = "0x91c - Endpoint 16."]
    #[inline(always)]
    pub const fn devgrp_diepdmab0(&self) -> &DevgrpDiepdmab0 {
        &self.devgrp_diepdmab0
    }
    #[doc = "0x920 - Endpoint_number: 1"]
    #[inline(always)]
    pub const fn devgrp_diepctl1(&self) -> &DevgrpDiepctl1 {
        &self.devgrp_diepctl1
    }
    #[doc = "0x928 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint1(&self) -> &DevgrpDiepint1 {
        &self.devgrp_diepint1
    }
    #[doc = "0x930 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz1(&self) -> &DevgrpDieptsiz1 {
        &self.devgrp_dieptsiz1
    }
    #[doc = "0x934 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma1(&self) -> &DevgrpDiepdma1 {
        &self.devgrp_diepdma1
    }
    #[doc = "0x938 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts1(&self) -> &DevgrpDtxfsts1 {
        &self.devgrp_dtxfsts1
    }
    #[doc = "0x93c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab1(&self) -> &DevgrpDiepdmab1 {
        &self.devgrp_diepdmab1
    }
    #[doc = "0x940 - Endpoint_number: 2"]
    #[inline(always)]
    pub const fn devgrp_diepctl2(&self) -> &DevgrpDiepctl2 {
        &self.devgrp_diepctl2
    }
    #[doc = "0x948 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint2(&self) -> &DevgrpDiepint2 {
        &self.devgrp_diepint2
    }
    #[doc = "0x950 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz2(&self) -> &DevgrpDieptsiz2 {
        &self.devgrp_dieptsiz2
    }
    #[doc = "0x954 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma2(&self) -> &DevgrpDiepdma2 {
        &self.devgrp_diepdma2
    }
    #[doc = "0x958 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts2(&self) -> &DevgrpDtxfsts2 {
        &self.devgrp_dtxfsts2
    }
    #[doc = "0x95c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab2(&self) -> &DevgrpDiepdmab2 {
        &self.devgrp_diepdmab2
    }
    #[doc = "0x960 - Endpoint_number: 3"]
    #[inline(always)]
    pub const fn devgrp_diepctl3(&self) -> &DevgrpDiepctl3 {
        &self.devgrp_diepctl3
    }
    #[doc = "0x968 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint3(&self) -> &DevgrpDiepint3 {
        &self.devgrp_diepint3
    }
    #[doc = "0x970 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz3(&self) -> &DevgrpDieptsiz3 {
        &self.devgrp_dieptsiz3
    }
    #[doc = "0x974 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma3(&self) -> &DevgrpDiepdma3 {
        &self.devgrp_diepdma3
    }
    #[doc = "0x978 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts3(&self) -> &DevgrpDtxfsts3 {
        &self.devgrp_dtxfsts3
    }
    #[doc = "0x97c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab3(&self) -> &DevgrpDiepdmab3 {
        &self.devgrp_diepdmab3
    }
    #[doc = "0x980 - Endpoint_number: 4"]
    #[inline(always)]
    pub const fn devgrp_diepctl4(&self) -> &DevgrpDiepctl4 {
        &self.devgrp_diepctl4
    }
    #[doc = "0x988 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint4(&self) -> &DevgrpDiepint4 {
        &self.devgrp_diepint4
    }
    #[doc = "0x990 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz4(&self) -> &DevgrpDieptsiz4 {
        &self.devgrp_dieptsiz4
    }
    #[doc = "0x994 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma4(&self) -> &DevgrpDiepdma4 {
        &self.devgrp_diepdma4
    }
    #[doc = "0x998 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts4(&self) -> &DevgrpDtxfsts4 {
        &self.devgrp_dtxfsts4
    }
    #[doc = "0x99c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab4(&self) -> &DevgrpDiepdmab4 {
        &self.devgrp_diepdmab4
    }
    #[doc = "0x9a0 - Endpoint_number: 5"]
    #[inline(always)]
    pub const fn devgrp_diepctl5(&self) -> &DevgrpDiepctl5 {
        &self.devgrp_diepctl5
    }
    #[doc = "0x9a8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint5(&self) -> &DevgrpDiepint5 {
        &self.devgrp_diepint5
    }
    #[doc = "0x9b0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz5(&self) -> &DevgrpDieptsiz5 {
        &self.devgrp_dieptsiz5
    }
    #[doc = "0x9b4 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma5(&self) -> &DevgrpDiepdma5 {
        &self.devgrp_diepdma5
    }
    #[doc = "0x9b8 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts5(&self) -> &DevgrpDtxfsts5 {
        &self.devgrp_dtxfsts5
    }
    #[doc = "0x9bc - Device IN Endpoint 1 Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab5(&self) -> &DevgrpDiepdmab5 {
        &self.devgrp_diepdmab5
    }
    #[doc = "0x9c0 - Endpoint_number: 6"]
    #[inline(always)]
    pub const fn devgrp_diepctl6(&self) -> &DevgrpDiepctl6 {
        &self.devgrp_diepctl6
    }
    #[doc = "0x9c8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint6(&self) -> &DevgrpDiepint6 {
        &self.devgrp_diepint6
    }
    #[doc = "0x9d0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz6(&self) -> &DevgrpDieptsiz6 {
        &self.devgrp_dieptsiz6
    }
    #[doc = "0x9d4 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma6(&self) -> &DevgrpDiepdma6 {
        &self.devgrp_diepdma6
    }
    #[doc = "0x9d8 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts6(&self) -> &DevgrpDtxfsts6 {
        &self.devgrp_dtxfsts6
    }
    #[doc = "0x9dc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab6(&self) -> &DevgrpDiepdmab6 {
        &self.devgrp_diepdmab6
    }
    #[doc = "0x9e0 - Endpoint_number: 7"]
    #[inline(always)]
    pub const fn devgrp_diepctl7(&self) -> &DevgrpDiepctl7 {
        &self.devgrp_diepctl7
    }
    #[doc = "0x9e8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint7(&self) -> &DevgrpDiepint7 {
        &self.devgrp_diepint7
    }
    #[doc = "0x9f0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz7(&self) -> &DevgrpDieptsiz7 {
        &self.devgrp_dieptsiz7
    }
    #[doc = "0x9f4 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma7(&self) -> &DevgrpDiepdma7 {
        &self.devgrp_diepdma7
    }
    #[doc = "0x9f8 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts7(&self) -> &DevgrpDtxfsts7 {
        &self.devgrp_dtxfsts7
    }
    #[doc = "0x9fc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab7(&self) -> &DevgrpDiepdmab7 {
        &self.devgrp_diepdmab7
    }
    #[doc = "0xa00 - Endpoint_number: 8"]
    #[inline(always)]
    pub const fn devgrp_diepctl8(&self) -> &DevgrpDiepctl8 {
        &self.devgrp_diepctl8
    }
    #[doc = "0xa08 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint8(&self) -> &DevgrpDiepint8 {
        &self.devgrp_diepint8
    }
    #[doc = "0xa10 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz8(&self) -> &DevgrpDieptsiz8 {
        &self.devgrp_dieptsiz8
    }
    #[doc = "0xa14 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma8(&self) -> &DevgrpDiepdma8 {
        &self.devgrp_diepdma8
    }
    #[doc = "0xa18 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts8(&self) -> &DevgrpDtxfsts8 {
        &self.devgrp_dtxfsts8
    }
    #[doc = "0xa1c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab8(&self) -> &DevgrpDiepdmab8 {
        &self.devgrp_diepdmab8
    }
    #[doc = "0xa20 - Endpoint_number: 9"]
    #[inline(always)]
    pub const fn devgrp_diepctl9(&self) -> &DevgrpDiepctl9 {
        &self.devgrp_diepctl9
    }
    #[doc = "0xa28 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint9(&self) -> &DevgrpDiepint9 {
        &self.devgrp_diepint9
    }
    #[doc = "0xa30 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz9(&self) -> &DevgrpDieptsiz9 {
        &self.devgrp_dieptsiz9
    }
    #[doc = "0xa34 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma9(&self) -> &DevgrpDiepdma9 {
        &self.devgrp_diepdma9
    }
    #[doc = "0xa38 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts9(&self) -> &DevgrpDtxfsts9 {
        &self.devgrp_dtxfsts9
    }
    #[doc = "0xa3c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab9(&self) -> &DevgrpDiepdmab9 {
        &self.devgrp_diepdmab9
    }
    #[doc = "0xa40 - Endpoint_number: 10"]
    #[inline(always)]
    pub const fn devgrp_diepctl10(&self) -> &DevgrpDiepctl10 {
        &self.devgrp_diepctl10
    }
    #[doc = "0xa48 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint10(&self) -> &DevgrpDiepint10 {
        &self.devgrp_diepint10
    }
    #[doc = "0xa50 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz10(&self) -> &DevgrpDieptsiz10 {
        &self.devgrp_dieptsiz10
    }
    #[doc = "0xa54 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma10(&self) -> &DevgrpDiepdma10 {
        &self.devgrp_diepdma10
    }
    #[doc = "0xa58 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts10(&self) -> &DevgrpDtxfsts10 {
        &self.devgrp_dtxfsts10
    }
    #[doc = "0xa5c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab10(&self) -> &DevgrpDiepdmab10 {
        &self.devgrp_diepdmab10
    }
    #[doc = "0xa60 - Endpoint_number: 11"]
    #[inline(always)]
    pub const fn devgrp_diepctl11(&self) -> &DevgrpDiepctl11 {
        &self.devgrp_diepctl11
    }
    #[doc = "0xa68 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint11(&self) -> &DevgrpDiepint11 {
        &self.devgrp_diepint11
    }
    #[doc = "0xa70 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz11(&self) -> &DevgrpDieptsiz11 {
        &self.devgrp_dieptsiz11
    }
    #[doc = "0xa74 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma11(&self) -> &DevgrpDiepdma11 {
        &self.devgrp_diepdma11
    }
    #[doc = "0xa78 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts11(&self) -> &DevgrpDtxfsts11 {
        &self.devgrp_dtxfsts11
    }
    #[doc = "0xa7c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab11(&self) -> &DevgrpDiepdmab11 {
        &self.devgrp_diepdmab11
    }
    #[doc = "0xa80 - Endpoint_number: 12"]
    #[inline(always)]
    pub const fn devgrp_diepctl12(&self) -> &DevgrpDiepctl12 {
        &self.devgrp_diepctl12
    }
    #[doc = "0xa88 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint12(&self) -> &DevgrpDiepint12 {
        &self.devgrp_diepint12
    }
    #[doc = "0xa90 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz12(&self) -> &DevgrpDieptsiz12 {
        &self.devgrp_dieptsiz12
    }
    #[doc = "0xa94 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma12(&self) -> &DevgrpDiepdma12 {
        &self.devgrp_diepdma12
    }
    #[doc = "0xa98 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts12(&self) -> &DevgrpDtxfsts12 {
        &self.devgrp_dtxfsts12
    }
    #[doc = "0xa9c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab12(&self) -> &DevgrpDiepdmab12 {
        &self.devgrp_diepdmab12
    }
    #[doc = "0xaa0 - Endpoint_number: 13"]
    #[inline(always)]
    pub const fn devgrp_diepctl13(&self) -> &DevgrpDiepctl13 {
        &self.devgrp_diepctl13
    }
    #[doc = "0xaa8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint13(&self) -> &DevgrpDiepint13 {
        &self.devgrp_diepint13
    }
    #[doc = "0xab0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz13(&self) -> &DevgrpDieptsiz13 {
        &self.devgrp_dieptsiz13
    }
    #[doc = "0xab4 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma13(&self) -> &DevgrpDiepdma13 {
        &self.devgrp_diepdma13
    }
    #[doc = "0xab8 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts13(&self) -> &DevgrpDtxfsts13 {
        &self.devgrp_dtxfsts13
    }
    #[doc = "0xabc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab13(&self) -> &DevgrpDiepdmab13 {
        &self.devgrp_diepdmab13
    }
    #[doc = "0xac0 - Endpoint_number: 14"]
    #[inline(always)]
    pub const fn devgrp_diepctl14(&self) -> &DevgrpDiepctl14 {
        &self.devgrp_diepctl14
    }
    #[doc = "0xac8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint14(&self) -> &DevgrpDiepint14 {
        &self.devgrp_diepint14
    }
    #[doc = "0xad0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz14(&self) -> &DevgrpDieptsiz14 {
        &self.devgrp_dieptsiz14
    }
    #[doc = "0xad4 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma14(&self) -> &DevgrpDiepdma14 {
        &self.devgrp_diepdma14
    }
    #[doc = "0xad8 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts14(&self) -> &DevgrpDtxfsts14 {
        &self.devgrp_dtxfsts14
    }
    #[doc = "0xadc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab14(&self) -> &DevgrpDiepdmab14 {
        &self.devgrp_diepdmab14
    }
    #[doc = "0xae0 - Endpoint_number: 15"]
    #[inline(always)]
    pub const fn devgrp_diepctl15(&self) -> &DevgrpDiepctl15 {
        &self.devgrp_diepctl15
    }
    #[doc = "0xae8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_diepint15(&self) -> &DevgrpDiepint15 {
        &self.devgrp_diepint15
    }
    #[doc = "0xaf0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_dieptsiz15(&self) -> &DevgrpDieptsiz15 {
        &self.devgrp_dieptsiz15
    }
    #[doc = "0xaf4 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_diepdma15(&self) -> &DevgrpDiepdma15 {
        &self.devgrp_diepdma15
    }
    #[doc = "0xaf8 - This register contains the free space information for the Device IN endpoint TxFIFO."]
    #[inline(always)]
    pub const fn devgrp_dtxfsts15(&self) -> &DevgrpDtxfsts15 {
        &self.devgrp_dtxfsts15
    }
    #[doc = "0xafc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_diepdmab15(&self) -> &DevgrpDiepdmab15 {
        &self.devgrp_diepdmab15
    }
    #[doc = "0xb00 - This is Control OUT Endpoint 0 Control register."]
    #[inline(always)]
    pub const fn devgrp_doepctl0(&self) -> &DevgrpDoepctl0 {
        &self.devgrp_doepctl0
    }
    #[doc = "0xb08 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint0(&self) -> &DevgrpDoepint0 {
        &self.devgrp_doepint0
    }
    #[doc = "0xb10 - The application must modify this register before enabling endpoint 0. Once endpoint 0 is enabled using Endpoint Enable bit of the Device Control Endpoint 0 Control registers (DIEPCTL0.EPEna/DOEPCTL0.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit. Nonzero endpoints use the registers for endpoints 1 to 15. When Scatter/Gather DMA mode is enabled, this register must not be programmed by the application. If the application reads this register when Scatter/Gather DMA mode is enabled, the core returns all zeros."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz0(&self) -> &DevgrpDoeptsiz0 {
        &self.devgrp_doeptsiz0
    }
    #[doc = "0xb14 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_doepdma0(&self) -> &DevgrpDoepdma0 {
        &self.devgrp_doepdma0
    }
    #[doc = "0xb1c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab0(&self) -> &DevgrpDoepdmab0 {
        &self.devgrp_doepdmab0
    }
    #[doc = "0xb20 - Out Endpoint 1."]
    #[inline(always)]
    pub const fn devgrp_doepctl1(&self) -> &DevgrpDoepctl1 {
        &self.devgrp_doepctl1
    }
    #[doc = "0xb28 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint1(&self) -> &DevgrpDoepint1 {
        &self.devgrp_doepint1
    }
    #[doc = "0xb30 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz1(&self) -> &DevgrpDoeptsiz1 {
        &self.devgrp_doeptsiz1
    }
    #[doc = "0xb34 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_doepdma1(&self) -> &DevgrpDoepdma1 {
        &self.devgrp_doepdma1
    }
    #[doc = "0xb3c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab1(&self) -> &DevgrpDoepdmab1 {
        &self.devgrp_doepdmab1
    }
    #[doc = "0xb40 - Out Endpoint 2."]
    #[inline(always)]
    pub const fn devgrp_doepctl2(&self) -> &DevgrpDoepctl2 {
        &self.devgrp_doepctl2
    }
    #[doc = "0xb48 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint2(&self) -> &DevgrpDoepint2 {
        &self.devgrp_doepint2
    }
    #[doc = "0xb50 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz2(&self) -> &DevgrpDoeptsiz2 {
        &self.devgrp_doeptsiz2
    }
    #[doc = "0xb54 - DMA Addressing."]
    #[inline(always)]
    pub const fn devgrp_doepdma2(&self) -> &DevgrpDoepdma2 {
        &self.devgrp_doepdma2
    }
    #[doc = "0xb5c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab2(&self) -> &DevgrpDoepdmab2 {
        &self.devgrp_doepdmab2
    }
    #[doc = "0xb60 - Out Endpoint 3."]
    #[inline(always)]
    pub const fn devgrp_doepctl3(&self) -> &DevgrpDoepctl3 {
        &self.devgrp_doepctl3
    }
    #[doc = "0xb68 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint3(&self) -> &DevgrpDoepint3 {
        &self.devgrp_doepint3
    }
    #[doc = "0xb70 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz3(&self) -> &DevgrpDoeptsiz3 {
        &self.devgrp_doeptsiz3
    }
    #[doc = "0xb74 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma3(&self) -> &DevgrpDoepdma3 {
        &self.devgrp_doepdma3
    }
    #[doc = "0xb7c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab3(&self) -> &DevgrpDoepdmab3 {
        &self.devgrp_doepdmab3
    }
    #[doc = "0xb80 - Out Endpoint 4."]
    #[inline(always)]
    pub const fn devgrp_doepctl4(&self) -> &DevgrpDoepctl4 {
        &self.devgrp_doepctl4
    }
    #[doc = "0xb88 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint4(&self) -> &DevgrpDoepint4 {
        &self.devgrp_doepint4
    }
    #[doc = "0xb90 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz4(&self) -> &DevgrpDoeptsiz4 {
        &self.devgrp_doeptsiz4
    }
    #[doc = "0xb94 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma4(&self) -> &DevgrpDoepdma4 {
        &self.devgrp_doepdma4
    }
    #[doc = "0xb9c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab4(&self) -> &DevgrpDoepdmab4 {
        &self.devgrp_doepdmab4
    }
    #[doc = "0xba0 - Out Endpoint 5."]
    #[inline(always)]
    pub const fn devgrp_doepctl5(&self) -> &DevgrpDoepctl5 {
        &self.devgrp_doepctl5
    }
    #[doc = "0xba8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint5(&self) -> &DevgrpDoepint5 {
        &self.devgrp_doepint5
    }
    #[doc = "0xbb0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz5(&self) -> &DevgrpDoeptsiz5 {
        &self.devgrp_doeptsiz5
    }
    #[doc = "0xbb4 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma5(&self) -> &DevgrpDoepdma5 {
        &self.devgrp_doepdma5
    }
    #[doc = "0xbbc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab5(&self) -> &DevgrpDoepdmab5 {
        &self.devgrp_doepdmab5
    }
    #[doc = "0xbc0 - Out Endpoint 6."]
    #[inline(always)]
    pub const fn devgrp_doepctl6(&self) -> &DevgrpDoepctl6 {
        &self.devgrp_doepctl6
    }
    #[doc = "0xbc8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint6(&self) -> &DevgrpDoepint6 {
        &self.devgrp_doepint6
    }
    #[doc = "0xbd0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz6(&self) -> &DevgrpDoeptsiz6 {
        &self.devgrp_doeptsiz6
    }
    #[doc = "0xbd4 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma6(&self) -> &DevgrpDoepdma6 {
        &self.devgrp_doepdma6
    }
    #[doc = "0xbdc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab6(&self) -> &DevgrpDoepdmab6 {
        &self.devgrp_doepdmab6
    }
    #[doc = "0xbe0 - Endpoint_number: 7"]
    #[inline(always)]
    pub const fn devgrp_doepctl7(&self) -> &DevgrpDoepctl7 {
        &self.devgrp_doepctl7
    }
    #[doc = "0xbe8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint7(&self) -> &DevgrpDoepint7 {
        &self.devgrp_doepint7
    }
    #[doc = "0xbf0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz7(&self) -> &DevgrpDoeptsiz7 {
        &self.devgrp_doeptsiz7
    }
    #[doc = "0xbf4 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma7(&self) -> &DevgrpDoepdma7 {
        &self.devgrp_doepdma7
    }
    #[doc = "0xbfc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab7(&self) -> &DevgrpDoepdmab7 {
        &self.devgrp_doepdmab7
    }
    #[doc = "0xc00 - Out Endpoint 8."]
    #[inline(always)]
    pub const fn devgrp_doepctl8(&self) -> &DevgrpDoepctl8 {
        &self.devgrp_doepctl8
    }
    #[doc = "0xc08 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint8(&self) -> &DevgrpDoepint8 {
        &self.devgrp_doepint8
    }
    #[doc = "0xc10 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz8(&self) -> &DevgrpDoeptsiz8 {
        &self.devgrp_doeptsiz8
    }
    #[doc = "0xc14 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma8(&self) -> &DevgrpDoepdma8 {
        &self.devgrp_doepdma8
    }
    #[doc = "0xc1c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab8(&self) -> &DevgrpDoepdmab8 {
        &self.devgrp_doepdmab8
    }
    #[doc = "0xc20 - Out Endpoint 9."]
    #[inline(always)]
    pub const fn devgrp_doepctl9(&self) -> &DevgrpDoepctl9 {
        &self.devgrp_doepctl9
    }
    #[doc = "0xc28 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint9(&self) -> &DevgrpDoepint9 {
        &self.devgrp_doepint9
    }
    #[doc = "0xc30 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz9(&self) -> &DevgrpDoeptsiz9 {
        &self.devgrp_doeptsiz9
    }
    #[doc = "0xc34 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma9(&self) -> &DevgrpDoepdma9 {
        &self.devgrp_doepdma9
    }
    #[doc = "0xc3c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab9(&self) -> &DevgrpDoepdmab9 {
        &self.devgrp_doepdmab9
    }
    #[doc = "0xc40 - Out Endpoint 10."]
    #[inline(always)]
    pub const fn devgrp_doepctl10(&self) -> &DevgrpDoepctl10 {
        &self.devgrp_doepctl10
    }
    #[doc = "0xc48 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint10(&self) -> &DevgrpDoepint10 {
        &self.devgrp_doepint10
    }
    #[doc = "0xc50 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz10(&self) -> &DevgrpDoeptsiz10 {
        &self.devgrp_doeptsiz10
    }
    #[doc = "0xc54 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma10(&self) -> &DevgrpDoepdma10 {
        &self.devgrp_doepdma10
    }
    #[doc = "0xc5c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab10(&self) -> &DevgrpDoepdmab10 {
        &self.devgrp_doepdmab10
    }
    #[doc = "0xc60 - Out Endpoint 11."]
    #[inline(always)]
    pub const fn devgrp_doepctl11(&self) -> &DevgrpDoepctl11 {
        &self.devgrp_doepctl11
    }
    #[doc = "0xc68 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint11(&self) -> &DevgrpDoepint11 {
        &self.devgrp_doepint11
    }
    #[doc = "0xc70 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz11(&self) -> &DevgrpDoeptsiz11 {
        &self.devgrp_doeptsiz11
    }
    #[doc = "0xc74 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma11(&self) -> &DevgrpDoepdma11 {
        &self.devgrp_doepdma11
    }
    #[doc = "0xc7c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab11(&self) -> &DevgrpDoepdmab11 {
        &self.devgrp_doepdmab11
    }
    #[doc = "0xc80 - Out Endpoint 12."]
    #[inline(always)]
    pub const fn devgrp_doepctl12(&self) -> &DevgrpDoepctl12 {
        &self.devgrp_doepctl12
    }
    #[doc = "0xc88 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint12(&self) -> &DevgrpDoepint12 {
        &self.devgrp_doepint12
    }
    #[doc = "0xc90 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz12(&self) -> &DevgrpDoeptsiz12 {
        &self.devgrp_doeptsiz12
    }
    #[doc = "0xc94 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma12(&self) -> &DevgrpDoepdma12 {
        &self.devgrp_doepdma12
    }
    #[doc = "0xc9c - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab12(&self) -> &DevgrpDoepdmab12 {
        &self.devgrp_doepdmab12
    }
    #[doc = "0xca0 - Out Endpoint 13."]
    #[inline(always)]
    pub const fn devgrp_doepctl13(&self) -> &DevgrpDoepctl13 {
        &self.devgrp_doepctl13
    }
    #[doc = "0xca8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint13(&self) -> &DevgrpDoepint13 {
        &self.devgrp_doepint13
    }
    #[doc = "0xcb0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz13(&self) -> &DevgrpDoeptsiz13 {
        &self.devgrp_doeptsiz13
    }
    #[doc = "0xcb4 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma13(&self) -> &DevgrpDoepdma13 {
        &self.devgrp_doepdma13
    }
    #[doc = "0xcbc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab13(&self) -> &DevgrpDoepdmab13 {
        &self.devgrp_doepdmab13
    }
    #[doc = "0xcc0 - Out Endpoint 14."]
    #[inline(always)]
    pub const fn devgrp_doepctl14(&self) -> &DevgrpDoepctl14 {
        &self.devgrp_doepctl14
    }
    #[doc = "0xcc8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint14(&self) -> &DevgrpDoepint14 {
        &self.devgrp_doepint14
    }
    #[doc = "0xcd0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz14(&self) -> &DevgrpDoeptsiz14 {
        &self.devgrp_doeptsiz14
    }
    #[doc = "0xcd4 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma14(&self) -> &DevgrpDoepdma14 {
        &self.devgrp_doepdma14
    }
    #[doc = "0xcdc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab14(&self) -> &DevgrpDoepdmab14 {
        &self.devgrp_doepdmab14
    }
    #[doc = "0xce0 - Out Endpoint 15."]
    #[inline(always)]
    pub const fn devgrp_doepctl15(&self) -> &DevgrpDoepctl15 {
        &self.devgrp_doepctl15
    }
    #[doc = "0xce8 - This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
    #[inline(always)]
    pub const fn devgrp_doepint15(&self) -> &DevgrpDoepint15 {
        &self.devgrp_doepint15
    }
    #[doc = "0xcf0 - The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
    #[inline(always)]
    pub const fn devgrp_doeptsiz15(&self) -> &DevgrpDoeptsiz15 {
        &self.devgrp_doeptsiz15
    }
    #[doc = "0xcf4 - DMA OUT Address."]
    #[inline(always)]
    pub const fn devgrp_doepdma15(&self) -> &DevgrpDoepdma15 {
        &self.devgrp_doepdma15
    }
    #[doc = "0xcfc - DMA Buffer Address."]
    #[inline(always)]
    pub const fn devgrp_doepdmab15(&self) -> &DevgrpDoepdmab15 {
        &self.devgrp_doepdmab15
    }
    #[doc = "0xe00 - This register is available in Host and Device modes. The application can use this register to control the core's power-down and clock gating features. Because the CSR module is turned off during power-down, this register is implemented in the AHB Slave BIU module."]
    #[inline(always)]
    pub const fn pwrclkgrp_pcgcctl(&self) -> &PwrclkgrpPcgcctl {
        &self.pwrclkgrp_pcgcctl
    }
}
#[doc = "globgrp_gotgctl (rw) register accessor: The OTG Control and Status register controls the behavior and reflects the status of the OTG function.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gotgctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gotgctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gotgctl`]
module"]
#[doc(alias = "globgrp_gotgctl")]
pub type GlobgrpGotgctl = crate::Reg<globgrp_gotgctl::GlobgrpGotgctlSpec>;
#[doc = "The OTG Control and Status register controls the behavior and reflects the status of the OTG function."]
pub mod globgrp_gotgctl;
#[doc = "globgrp_gotgint (r) register accessor: The application reads this register whenever there is an OTG interrupt and clears the bits in this register to clear the OTG interrupt.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gotgint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gotgint`]
module"]
#[doc(alias = "globgrp_gotgint")]
pub type GlobgrpGotgint = crate::Reg<globgrp_gotgint::GlobgrpGotgintSpec>;
#[doc = "The application reads this register whenever there is an OTG interrupt and clears the bits in this register to clear the OTG interrupt."]
pub mod globgrp_gotgint;
#[doc = "globgrp_gahbcfg (rw) register accessor: This register can be used to configure the core after power-on or a change in mode. This register mainly contains AHB system-related configuration parameters. Do not change this register after the initial programming. The application must program this register before starting any transactions on either the AHB or the USB.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gahbcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gahbcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gahbcfg`]
module"]
#[doc(alias = "globgrp_gahbcfg")]
pub type GlobgrpGahbcfg = crate::Reg<globgrp_gahbcfg::GlobgrpGahbcfgSpec>;
#[doc = "This register can be used to configure the core after power-on or a change in mode. This register mainly contains AHB system-related configuration parameters. Do not change this register after the initial programming. The application must program this register before starting any transactions on either the AHB or the USB."]
pub mod globgrp_gahbcfg;
#[doc = "globgrp_gusbcfg (rw) register accessor: This register can be used to configure the core after power-on or a changing to Host mode or Device mode. It contains USB and USB-PHY related configuration parameters. The application must program this register before starting any transactions on either the AHB or the USB. Do not make changes to this register after the initial programming.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gusbcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gusbcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gusbcfg`]
module"]
#[doc(alias = "globgrp_gusbcfg")]
pub type GlobgrpGusbcfg = crate::Reg<globgrp_gusbcfg::GlobgrpGusbcfgSpec>;
#[doc = "This register can be used to configure the core after power-on or a changing to Host mode or Device mode. It contains USB and USB-PHY related configuration parameters. The application must program this register before starting any transactions on either the AHB or the USB. Do not make changes to this register after the initial programming."]
pub mod globgrp_gusbcfg;
#[doc = "globgrp_grstctl (rw) register accessor: The application uses this register to reset various hardware features inside the core\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_grstctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_grstctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_grstctl`]
module"]
#[doc(alias = "globgrp_grstctl")]
pub type GlobgrpGrstctl = crate::Reg<globgrp_grstctl::GlobgrpGrstctlSpec>;
#[doc = "The application uses this register to reset various hardware features inside the core"]
pub mod globgrp_grstctl;
#[doc = "globgrp_gintsts (r) register accessor: This register interrupts the application for system-level events in the current mode (Device mode or Host mode). Some of the bits in this register are valid only in Host mode, while others are valid in Device mode only. This register also indicates the current mode. To clear the interrupt status bits of type R_SS_WC, the application must write 1 into the bit. The FIFO status interrupts are read only; once software reads from or writes to the FIFO while servicing these interrupts, FIFO interrupt conditions are cleared automatically. The application must clear the GINTSTS register at initialization before unmasking the interrupt bit to avoid any interrupts generated prior to initialization.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gintsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gintsts`]
module"]
#[doc(alias = "globgrp_gintsts")]
pub type GlobgrpGintsts = crate::Reg<globgrp_gintsts::GlobgrpGintstsSpec>;
#[doc = "This register interrupts the application for system-level events in the current mode (Device mode or Host mode). Some of the bits in this register are valid only in Host mode, while others are valid in Device mode only. This register also indicates the current mode. To clear the interrupt status bits of type R_SS_WC, the application must write 1 into the bit. The FIFO status interrupts are read only; once software reads from or writes to the FIFO while servicing these interrupts, FIFO interrupt conditions are cleared automatically. The application must clear the GINTSTS register at initialization before unmasking the interrupt bit to avoid any interrupts generated prior to initialization."]
pub mod globgrp_gintsts;
#[doc = "globgrp_gintmsk (rw) register accessor: This register works with the Interrupt Register (GINTSTS) to interrupt the application. When an interrupt bit is masked, the interrupt associated with that bit is not generated. However, the GINTSTS register bit corresponding to that interrupt is still set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gintmsk`]
module"]
#[doc(alias = "globgrp_gintmsk")]
pub type GlobgrpGintmsk = crate::Reg<globgrp_gintmsk::GlobgrpGintmskSpec>;
#[doc = "This register works with the Interrupt Register (GINTSTS) to interrupt the application. When an interrupt bit is masked, the interrupt associated with that bit is not generated. However, the GINTSTS register bit corresponding to that interrupt is still set."]
pub mod globgrp_gintmsk;
#[doc = "globgrp_grxstsr (r) register accessor: A read to the Receive Status Read and Pop register additionally pops the: top data entry out of the RxFIFO. The receive status contents must be interpreted differently in Host and Device modes. The core ignores the receive status pop/read when the receive FIFO is empty and returns a value of 0. The application must only pop the Receive Status FIFO when the Receive FIFO Non-Empty bit of the Core Interrupt register (GINTSTS.RxFLvl) is asserted. Use of these fields vary based on whether the HS OTG core is functioning as a host or a device. Do not read this register's reset value before configuring the core because the read value is \"X\" in the simulation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_grxstsr::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_grxstsr`]
module"]
#[doc(alias = "globgrp_grxstsr")]
pub type GlobgrpGrxstsr = crate::Reg<globgrp_grxstsr::GlobgrpGrxstsrSpec>;
#[doc = "A read to the Receive Status Read and Pop register additionally pops the: top data entry out of the RxFIFO. The receive status contents must be interpreted differently in Host and Device modes. The core ignores the receive status pop/read when the receive FIFO is empty and returns a value of 0. The application must only pop the Receive Status FIFO when the Receive FIFO Non-Empty bit of the Core Interrupt register (GINTSTS.RxFLvl) is asserted. Use of these fields vary based on whether the HS OTG core is functioning as a host or a device. Do not read this register's reset value before configuring the core because the read value is \"X\" in the simulation."]
pub mod globgrp_grxstsr;
#[doc = "globgrp_grxstsp (r) register accessor: A read to the Receive Status Read and Pop register additionally pops the: top data entry out of the RxFIFO. The receive status contents must be interpreted differently in Host and Device modes. The core ignores the receive status pop/read when the receive FIFO is empty and returns a value of 0. The application must only pop the Receive Status FIFO when the Receive FIFO Non-Empty bit of the Core Interrupt register (GINTSTS.RxFLvl) is asserted. Use of these fields vary based on whether the HS OTG core is functioning as a host or a device. Do not read this register'ss reset value before configuring the core because the read value is \"X\" in the simulation.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_grxstsp::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_grxstsp`]
module"]
#[doc(alias = "globgrp_grxstsp")]
pub type GlobgrpGrxstsp = crate::Reg<globgrp_grxstsp::GlobgrpGrxstspSpec>;
#[doc = "A read to the Receive Status Read and Pop register additionally pops the: top data entry out of the RxFIFO. The receive status contents must be interpreted differently in Host and Device modes. The core ignores the receive status pop/read when the receive FIFO is empty and returns a value of 0. The application must only pop the Receive Status FIFO when the Receive FIFO Non-Empty bit of the Core Interrupt register (GINTSTS.RxFLvl) is asserted. Use of these fields vary based on whether the HS OTG core is functioning as a host or a device. Do not read this register'ss reset value before configuring the core because the read value is \"X\" in the simulation."]
pub mod globgrp_grxstsp;
#[doc = "globgrp_grxfsiz (rw) register accessor: The application can program the RAM size that must be allocated to the RxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_grxfsiz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_grxfsiz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_grxfsiz`]
module"]
#[doc(alias = "globgrp_grxfsiz")]
pub type GlobgrpGrxfsiz = crate::Reg<globgrp_grxfsiz::GlobgrpGrxfsizSpec>;
#[doc = "The application can program the RAM size that must be allocated to the RxFIFO."]
pub mod globgrp_grxfsiz;
#[doc = "globgrp_gnptxfsiz (rw) register accessor: The application can program the RAM size and the memory start address for the Non-periodic TxFIFO. The fields of this register change, depending on host or device mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gnptxfsiz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gnptxfsiz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gnptxfsiz`]
module"]
#[doc(alias = "globgrp_gnptxfsiz")]
pub type GlobgrpGnptxfsiz = crate::Reg<globgrp_gnptxfsiz::GlobgrpGnptxfsizSpec>;
#[doc = "The application can program the RAM size and the memory start address for the Non-periodic TxFIFO. The fields of this register change, depending on host or device mode."]
pub mod globgrp_gnptxfsiz;
#[doc = "globgrp_gnptxsts (r) register accessor: In Device mode, this register is valid only in Shared FIFO operation. It contains the free space information for the Non-periodic TxFIFO and the Nonperiodic Transmit RequestQueue\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gnptxsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gnptxsts`]
module"]
#[doc(alias = "globgrp_gnptxsts")]
pub type GlobgrpGnptxsts = crate::Reg<globgrp_gnptxsts::GlobgrpGnptxstsSpec>;
#[doc = "In Device mode, this register is valid only in Shared FIFO operation. It contains the free space information for the Non-periodic TxFIFO and the Nonperiodic Transmit RequestQueue"]
pub mod globgrp_gnptxsts;
#[doc = "globgrp_gpvndctl (rw) register accessor: The application can use this register to access PHY registers. for a ULPI PHY, the core uses the ULPI interface for PHY register access. The application sets Vendor Control register for PHY register access and times the PHY register access. The application polls the VStatus Done bit in this register for the completion of the PHY register access\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gpvndctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gpvndctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gpvndctl`]
module"]
#[doc(alias = "globgrp_gpvndctl")]
pub type GlobgrpGpvndctl = crate::Reg<globgrp_gpvndctl::GlobgrpGpvndctlSpec>;
#[doc = "The application can use this register to access PHY registers. for a ULPI PHY, the core uses the ULPI interface for PHY register access. The application sets Vendor Control register for PHY register access and times the PHY register access. The application polls the VStatus Done bit in this register for the completion of the PHY register access"]
pub mod globgrp_gpvndctl;
#[doc = "globgrp_ggpio (rw) register accessor: The application can use this register for general purpose input/output ports or for debugging.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ggpio::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_ggpio::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_ggpio`]
module"]
#[doc(alias = "globgrp_ggpio")]
pub type GlobgrpGgpio = crate::Reg<globgrp_ggpio::GlobgrpGgpioSpec>;
#[doc = "The application can use this register for general purpose input/output ports or for debugging."]
pub mod globgrp_ggpio;
#[doc = "globgrp_guid (rw) register accessor: This is a read/write register containing the User ID. This register can be used in the following ways: -To store the version or revision of your system -To store hardware configurations that are outside the otg core As a scratch register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_guid::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_guid::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_guid`]
module"]
#[doc(alias = "globgrp_guid")]
pub type GlobgrpGuid = crate::Reg<globgrp_guid::GlobgrpGuidSpec>;
#[doc = "This is a read/write register containing the User ID. This register can be used in the following ways: -To store the version or revision of your system -To store hardware configurations that are outside the otg core As a scratch register"]
pub mod globgrp_guid;
#[doc = "globgrp_gsnpsid (r) register accessor: This read-only register contains the release number of the core being used.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gsnpsid::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gsnpsid`]
module"]
#[doc(alias = "globgrp_gsnpsid")]
pub type GlobgrpGsnpsid = crate::Reg<globgrp_gsnpsid::GlobgrpGsnpsidSpec>;
#[doc = "This read-only register contains the release number of the core being used."]
pub mod globgrp_gsnpsid;
#[doc = "globgrp_ghwcfg1 (r) register accessor: This register contains the logical endpoint direction(s).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ghwcfg1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_ghwcfg1`]
module"]
#[doc(alias = "globgrp_ghwcfg1")]
pub type GlobgrpGhwcfg1 = crate::Reg<globgrp_ghwcfg1::GlobgrpGhwcfg1Spec>;
#[doc = "This register contains the logical endpoint direction(s)."]
pub mod globgrp_ghwcfg1;
#[doc = "globgrp_ghwcfg2 (r) register accessor: This register contains configuration options.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ghwcfg2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_ghwcfg2`]
module"]
#[doc(alias = "globgrp_ghwcfg2")]
pub type GlobgrpGhwcfg2 = crate::Reg<globgrp_ghwcfg2::GlobgrpGhwcfg2Spec>;
#[doc = "This register contains configuration options."]
pub mod globgrp_ghwcfg2;
#[doc = "globgrp_ghwcfg3 (r) register accessor: This register contains the configuration options.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ghwcfg3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_ghwcfg3`]
module"]
#[doc(alias = "globgrp_ghwcfg3")]
pub type GlobgrpGhwcfg3 = crate::Reg<globgrp_ghwcfg3::GlobgrpGhwcfg3Spec>;
#[doc = "This register contains the configuration options."]
pub mod globgrp_ghwcfg3;
#[doc = "globgrp_ghwcfg4 (r) register accessor: This register contains the configuration options.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_ghwcfg4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_ghwcfg4`]
module"]
#[doc(alias = "globgrp_ghwcfg4")]
pub type GlobgrpGhwcfg4 = crate::Reg<globgrp_ghwcfg4::GlobgrpGhwcfg4Spec>;
#[doc = "This register contains the configuration options."]
pub mod globgrp_ghwcfg4;
#[doc = "globgrp_gdfifocfg (rw) register accessor: Specifies whether Dedicated Transmit FIFOs should be enabled in device mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_gdfifocfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_gdfifocfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_gdfifocfg`]
module"]
#[doc(alias = "globgrp_gdfifocfg")]
pub type GlobgrpGdfifocfg = crate::Reg<globgrp_gdfifocfg::GlobgrpGdfifocfgSpec>;
#[doc = "Specifies whether Dedicated Transmit FIFOs should be enabled in device mode."]
pub mod globgrp_gdfifocfg;
#[doc = "globgrp_hptxfsiz (rw) register accessor: This register holds the size and the memory start address of the Periodic TxFIFO\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_hptxfsiz::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_hptxfsiz::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_hptxfsiz`]
module"]
#[doc(alias = "globgrp_hptxfsiz")]
pub type GlobgrpHptxfsiz = crate::Reg<globgrp_hptxfsiz::GlobgrpHptxfsizSpec>;
#[doc = "This register holds the size and the memory start address of the Periodic TxFIFO"]
pub mod globgrp_hptxfsiz;
#[doc = "globgrp_dieptxf1 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf1`]
module"]
#[doc(alias = "globgrp_dieptxf1")]
pub type GlobgrpDieptxf1 = crate::Reg<globgrp_dieptxf1::GlobgrpDieptxf1Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf1;
#[doc = "globgrp_dieptxf2 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf2`]
module"]
#[doc(alias = "globgrp_dieptxf2")]
pub type GlobgrpDieptxf2 = crate::Reg<globgrp_dieptxf2::GlobgrpDieptxf2Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf2;
#[doc = "globgrp_dieptxf3 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf3`]
module"]
#[doc(alias = "globgrp_dieptxf3")]
pub type GlobgrpDieptxf3 = crate::Reg<globgrp_dieptxf3::GlobgrpDieptxf3Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf3;
#[doc = "globgrp_dieptxf4 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf4`]
module"]
#[doc(alias = "globgrp_dieptxf4")]
pub type GlobgrpDieptxf4 = crate::Reg<globgrp_dieptxf4::GlobgrpDieptxf4Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf4;
#[doc = "globgrp_dieptxf5 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf5`]
module"]
#[doc(alias = "globgrp_dieptxf5")]
pub type GlobgrpDieptxf5 = crate::Reg<globgrp_dieptxf5::GlobgrpDieptxf5Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf5;
#[doc = "globgrp_dieptxf6 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf6`]
module"]
#[doc(alias = "globgrp_dieptxf6")]
pub type GlobgrpDieptxf6 = crate::Reg<globgrp_dieptxf6::GlobgrpDieptxf6Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf6;
#[doc = "globgrp_dieptxf7 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf7`]
module"]
#[doc(alias = "globgrp_dieptxf7")]
pub type GlobgrpDieptxf7 = crate::Reg<globgrp_dieptxf7::GlobgrpDieptxf7Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf7;
#[doc = "globgrp_dieptxf8 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf8`]
module"]
#[doc(alias = "globgrp_dieptxf8")]
pub type GlobgrpDieptxf8 = crate::Reg<globgrp_dieptxf8::GlobgrpDieptxf8Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf8;
#[doc = "globgrp_dieptxf9 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf9`]
module"]
#[doc(alias = "globgrp_dieptxf9")]
pub type GlobgrpDieptxf9 = crate::Reg<globgrp_dieptxf9::GlobgrpDieptxf9Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf9;
#[doc = "globgrp_dieptxf10 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf10`]
module"]
#[doc(alias = "globgrp_dieptxf10")]
pub type GlobgrpDieptxf10 = crate::Reg<globgrp_dieptxf10::GlobgrpDieptxf10Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf10;
#[doc = "globgrp_dieptxf11 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf11`]
module"]
#[doc(alias = "globgrp_dieptxf11")]
pub type GlobgrpDieptxf11 = crate::Reg<globgrp_dieptxf11::GlobgrpDieptxf11Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf11;
#[doc = "globgrp_dieptxf12 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf12`]
module"]
#[doc(alias = "globgrp_dieptxf12")]
pub type GlobgrpDieptxf12 = crate::Reg<globgrp_dieptxf12::GlobgrpDieptxf12Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf12;
#[doc = "globgrp_dieptxf13 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf13`]
module"]
#[doc(alias = "globgrp_dieptxf13")]
pub type GlobgrpDieptxf13 = crate::Reg<globgrp_dieptxf13::GlobgrpDieptxf13Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf13;
#[doc = "globgrp_dieptxf14 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf14`]
module"]
#[doc(alias = "globgrp_dieptxf14")]
pub type GlobgrpDieptxf14 = crate::Reg<globgrp_dieptxf14::GlobgrpDieptxf14Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf14;
#[doc = "globgrp_dieptxf15 (rw) register accessor: This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`globgrp_dieptxf15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`globgrp_dieptxf15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@globgrp_dieptxf15`]
module"]
#[doc(alias = "globgrp_dieptxf15")]
pub type GlobgrpDieptxf15 = crate::Reg<globgrp_dieptxf15::GlobgrpDieptxf15Spec>;
#[doc = "This register holds the size and memory start address of IN endpoint TxFIFOs implemented in Device mode. Each FIFO holds the data for one IN endpoint. This register is repeated for each instantiated IN endpoint FIFO. For IN endpoint FIFO 0 use GNPTXFSIZ register for programming the size and memory start address."]
pub mod globgrp_dieptxf15;
#[doc = "hostgrp_hcfg (rw) register accessor: Host Mode control. This register must be programmed every time the core changes to Host mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcfg`]
module"]
#[doc(alias = "hostgrp_hcfg")]
pub type HostgrpHcfg = crate::Reg<hostgrp_hcfg::HostgrpHcfgSpec>;
#[doc = "Host Mode control. This register must be programmed every time the core changes to Host mode"]
pub mod hostgrp_hcfg;
#[doc = "hostgrp_hfir (rw) register accessor: This register stores the frame interval information for the current speed to which the otg core has enumerated\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hfir::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hfir::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hfir`]
module"]
#[doc(alias = "hostgrp_hfir")]
pub type HostgrpHfir = crate::Reg<hostgrp_hfir::HostgrpHfirSpec>;
#[doc = "This register stores the frame interval information for the current speed to which the otg core has enumerated"]
pub mod hostgrp_hfir;
#[doc = "hostgrp_hfnum (r) register accessor: This register contains the free space information for the Periodic TxFIFO and the Periodic Transmit Request Queue\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hfnum::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hfnum`]
module"]
#[doc(alias = "hostgrp_hfnum")]
pub type HostgrpHfnum = crate::Reg<hostgrp_hfnum::HostgrpHfnumSpec>;
#[doc = "This register contains the free space information for the Periodic TxFIFO and the Periodic Transmit Request Queue"]
pub mod hostgrp_hfnum;
#[doc = "hostgrp_hptxsts (r) register accessor: This register contains the free space information for the Periodic TxFIFO and the Periodic Transmit Request Queue.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hptxsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hptxsts`]
module"]
#[doc(alias = "hostgrp_hptxsts")]
pub type HostgrpHptxsts = crate::Reg<hostgrp_hptxsts::HostgrpHptxstsSpec>;
#[doc = "This register contains the free space information for the Periodic TxFIFO and the Periodic Transmit Request Queue."]
pub mod hostgrp_hptxsts;
#[doc = "hostgrp_haint (r) register accessor: When a significant event occurs on a channel, the Host All Channels Interrupt register interrupts the application using the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt). There is one interrupt bit per channel, up to a maximum of 16 bits. Bits in this register are set and cleared when the application sets and clears bits in the corresponding Host Channel-n Interrupt register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_haint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_haint`]
module"]
#[doc(alias = "hostgrp_haint")]
pub type HostgrpHaint = crate::Reg<hostgrp_haint::HostgrpHaintSpec>;
#[doc = "When a significant event occurs on a channel, the Host All Channels Interrupt register interrupts the application using the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt). There is one interrupt bit per channel, up to a maximum of 16 bits. Bits in this register are set and cleared when the application sets and clears bits in the corresponding Host Channel-n Interrupt register."]
pub mod hostgrp_haint;
#[doc = "hostgrp_haintmsk (rw) register accessor: The Host All Channel Interrupt Mask register works with the Host All Channel Interrupt register to interrupt the application when an event occurs on a channel. There is one interrupt mask bit per channel, up to a maximum of 16 bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_haintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_haintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_haintmsk`]
module"]
#[doc(alias = "hostgrp_haintmsk")]
pub type HostgrpHaintmsk = crate::Reg<hostgrp_haintmsk::HostgrpHaintmskSpec>;
#[doc = "The Host All Channel Interrupt Mask register works with the Host All Channel Interrupt register to interrupt the application when an event occurs on a channel. There is one interrupt mask bit per channel, up to a maximum of 16 bits."]
pub mod hostgrp_haintmsk;
#[doc = "hostgrp_hflbaddr (rw) register accessor: This Register is valid only for Host mode Scatter-Gather DMA. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hflbaddr::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hflbaddr::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hflbaddr`]
module"]
#[doc(alias = "hostgrp_hflbaddr")]
pub type HostgrpHflbaddr = crate::Reg<hostgrp_hflbaddr::HostgrpHflbaddrSpec>;
#[doc = "This Register is valid only for Host mode Scatter-Gather DMA. Starting address of the Frame list. This register is used only for Isochronous and Interrupt Channels."]
pub mod hostgrp_hflbaddr;
#[doc = "hostgrp_hprt (rw) register accessor: This register is available only in Host mode. Currently, the OTG Host supports only one port. A single register holds USB port-related information such as USB reset, enable, suspend, resume, connect status, and test mode for each port.The R_SS_WC bits in this register can trigger an interrupt to the application through the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). On a Port Interrupt, the application must read this register and clear the bit that caused the interrupt. for the R_SS_WC bits, the application must write a 1 to the bit to clear the interrupt\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hprt::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hprt::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hprt`]
module"]
#[doc(alias = "hostgrp_hprt")]
pub type HostgrpHprt = crate::Reg<hostgrp_hprt::HostgrpHprtSpec>;
#[doc = "This register is available only in Host mode. Currently, the OTG Host supports only one port. A single register holds USB port-related information such as USB reset, enable, suspend, resume, connect status, and test mode for each port.The R_SS_WC bits in this register can trigger an interrupt to the application through the Host Port Interrupt bit of the Core Interrupt register (GINTSTS.PrtInt). On a Port Interrupt, the application must read this register and clear the bit that caused the interrupt. for the R_SS_WC bits, the application must write a 1 to the bit to clear the interrupt"]
pub mod hostgrp_hprt;
#[doc = "hostgrp_hcchar0 (rw) register accessor: Channel_number: 0.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar0`]
module"]
#[doc(alias = "hostgrp_hcchar0")]
pub type HostgrpHcchar0 = crate::Reg<hostgrp_hcchar0::HostgrpHcchar0Spec>;
#[doc = "Channel_number: 0."]
pub mod hostgrp_hcchar0;
#[doc = "hostgrp_hcsplt0 (rw) register accessor: Channel_number 0\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt0`]
module"]
#[doc(alias = "hostgrp_hcsplt0")]
pub type HostgrpHcsplt0 = crate::Reg<hostgrp_hcsplt0::HostgrpHcsplt0Spec>;
#[doc = "Channel_number 0"]
pub mod hostgrp_hcsplt0;
#[doc = "hostgrp_hcint0 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint0`]
module"]
#[doc(alias = "hostgrp_hcint0")]
pub type HostgrpHcint0 = crate::Reg<hostgrp_hcint0::HostgrpHcint0Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint0;
#[doc = "hostgrp_hcintmsk0 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk0`]
module"]
#[doc(alias = "hostgrp_hcintmsk0")]
pub type HostgrpHcintmsk0 = crate::Reg<hostgrp_hcintmsk0::HostgrpHcintmsk0Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk0;
#[doc = "hostgrp_hctsiz0 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz0`]
module"]
#[doc(alias = "hostgrp_hctsiz0")]
pub type HostgrpHctsiz0 = crate::Reg<hostgrp_hctsiz0::HostgrpHctsiz0Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz0;
#[doc = "hostgrp_hcdma0 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma0`]
module"]
#[doc(alias = "hostgrp_hcdma0")]
pub type HostgrpHcdma0 = crate::Reg<hostgrp_hcdma0::HostgrpHcdma0Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma0;
#[doc = "hostgrp_hcdmab0 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab0`]
module"]
#[doc(alias = "hostgrp_hcdmab0")]
pub type HostgrpHcdmab0 = crate::Reg<hostgrp_hcdmab0::HostgrpHcdmab0Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab0;
#[doc = "hostgrp_hcchar1 (rw) register accessor: Host Channel 1 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar1`]
module"]
#[doc(alias = "hostgrp_hcchar1")]
pub type HostgrpHcchar1 = crate::Reg<hostgrp_hcchar1::HostgrpHcchar1Spec>;
#[doc = "Host Channel 1 Characteristics Register"]
pub mod hostgrp_hcchar1;
#[doc = "hostgrp_hcsplt1 (rw) register accessor: Channel_number 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt1`]
module"]
#[doc(alias = "hostgrp_hcsplt1")]
pub type HostgrpHcsplt1 = crate::Reg<hostgrp_hcsplt1::HostgrpHcsplt1Spec>;
#[doc = "Channel_number 1"]
pub mod hostgrp_hcsplt1;
#[doc = "hostgrp_hcint1 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint1`]
module"]
#[doc(alias = "hostgrp_hcint1")]
pub type HostgrpHcint1 = crate::Reg<hostgrp_hcint1::HostgrpHcint1Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint1;
#[doc = "hostgrp_hcintmsk1 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk1`]
module"]
#[doc(alias = "hostgrp_hcintmsk1")]
pub type HostgrpHcintmsk1 = crate::Reg<hostgrp_hcintmsk1::HostgrpHcintmsk1Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk1;
#[doc = "hostgrp_hctsiz1 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz1`]
module"]
#[doc(alias = "hostgrp_hctsiz1")]
pub type HostgrpHctsiz1 = crate::Reg<hostgrp_hctsiz1::HostgrpHctsiz1Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz1;
#[doc = "hostgrp_hcdma1 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma1`]
module"]
#[doc(alias = "hostgrp_hcdma1")]
pub type HostgrpHcdma1 = crate::Reg<hostgrp_hcdma1::HostgrpHcdma1Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma1;
#[doc = "hostgrp_hcdmab1 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab1`]
module"]
#[doc(alias = "hostgrp_hcdmab1")]
pub type HostgrpHcdmab1 = crate::Reg<hostgrp_hcdmab1::HostgrpHcdmab1Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab1;
#[doc = "hostgrp_hcchar2 (rw) register accessor: Host Channel 2 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar2`]
module"]
#[doc(alias = "hostgrp_hcchar2")]
pub type HostgrpHcchar2 = crate::Reg<hostgrp_hcchar2::HostgrpHcchar2Spec>;
#[doc = "Host Channel 2 Characteristics Register"]
pub mod hostgrp_hcchar2;
#[doc = "hostgrp_hcsplt2 (rw) register accessor: Channel_number 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt2`]
module"]
#[doc(alias = "hostgrp_hcsplt2")]
pub type HostgrpHcsplt2 = crate::Reg<hostgrp_hcsplt2::HostgrpHcsplt2Spec>;
#[doc = "Channel_number 2"]
pub mod hostgrp_hcsplt2;
#[doc = "hostgrp_hcint2 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint2`]
module"]
#[doc(alias = "hostgrp_hcint2")]
pub type HostgrpHcint2 = crate::Reg<hostgrp_hcint2::HostgrpHcint2Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint2;
#[doc = "hostgrp_hcintmsk2 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk2`]
module"]
#[doc(alias = "hostgrp_hcintmsk2")]
pub type HostgrpHcintmsk2 = crate::Reg<hostgrp_hcintmsk2::HostgrpHcintmsk2Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk2;
#[doc = "hostgrp_hctsiz2 (rw) register accessor: Buffer DMA Mode.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz2`]
module"]
#[doc(alias = "hostgrp_hctsiz2")]
pub type HostgrpHctsiz2 = crate::Reg<hostgrp_hctsiz2::HostgrpHctsiz2Spec>;
#[doc = "Buffer DMA Mode."]
pub mod hostgrp_hctsiz2;
#[doc = "hostgrp_hcdma2 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma2`]
module"]
#[doc(alias = "hostgrp_hcdma2")]
pub type HostgrpHcdma2 = crate::Reg<hostgrp_hcdma2::HostgrpHcdma2Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma2;
#[doc = "hostgrp_hcdmab2 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab2`]
module"]
#[doc(alias = "hostgrp_hcdmab2")]
pub type HostgrpHcdmab2 = crate::Reg<hostgrp_hcdmab2::HostgrpHcdmab2Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab2;
#[doc = "hostgrp_hcchar3 (rw) register accessor: Channel_number: 3.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar3`]
module"]
#[doc(alias = "hostgrp_hcchar3")]
pub type HostgrpHcchar3 = crate::Reg<hostgrp_hcchar3::HostgrpHcchar3Spec>;
#[doc = "Channel_number: 3."]
pub mod hostgrp_hcchar3;
#[doc = "hostgrp_hcsplt3 (rw) register accessor: Channel_number 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt3`]
module"]
#[doc(alias = "hostgrp_hcsplt3")]
pub type HostgrpHcsplt3 = crate::Reg<hostgrp_hcsplt3::HostgrpHcsplt3Spec>;
#[doc = "Channel_number 3"]
pub mod hostgrp_hcsplt3;
#[doc = "hostgrp_hcint3 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint3`]
module"]
#[doc(alias = "hostgrp_hcint3")]
pub type HostgrpHcint3 = crate::Reg<hostgrp_hcint3::HostgrpHcint3Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint3;
#[doc = "hostgrp_hcintmsk3 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk3`]
module"]
#[doc(alias = "hostgrp_hcintmsk3")]
pub type HostgrpHcintmsk3 = crate::Reg<hostgrp_hcintmsk3::HostgrpHcintmsk3Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk3;
#[doc = "hostgrp_hctsiz3 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz3`]
module"]
#[doc(alias = "hostgrp_hctsiz3")]
pub type HostgrpHctsiz3 = crate::Reg<hostgrp_hctsiz3::HostgrpHctsiz3Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz3;
#[doc = "hostgrp_hcdma3 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma3`]
module"]
#[doc(alias = "hostgrp_hcdma3")]
pub type HostgrpHcdma3 = crate::Reg<hostgrp_hcdma3::HostgrpHcdma3Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma3;
#[doc = "hostgrp_hcdmab3 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab3`]
module"]
#[doc(alias = "hostgrp_hcdmab3")]
pub type HostgrpHcdmab3 = crate::Reg<hostgrp_hcdmab3::HostgrpHcdmab3Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab3;
#[doc = "hostgrp_hcchar4 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar4`]
module"]
#[doc(alias = "hostgrp_hcchar4")]
pub type HostgrpHcchar4 = crate::Reg<hostgrp_hcchar4::HostgrpHcchar4Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcchar4;
#[doc = "hostgrp_hcsplt4 (rw) register accessor: Channel_number 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt4`]
module"]
#[doc(alias = "hostgrp_hcsplt4")]
pub type HostgrpHcsplt4 = crate::Reg<hostgrp_hcsplt4::HostgrpHcsplt4Spec>;
#[doc = "Channel_number 4"]
pub mod hostgrp_hcsplt4;
#[doc = "hostgrp_hcint4 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint4`]
module"]
#[doc(alias = "hostgrp_hcint4")]
pub type HostgrpHcint4 = crate::Reg<hostgrp_hcint4::HostgrpHcint4Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint4;
#[doc = "hostgrp_hcintmsk4 (rw) register accessor: This register reflects the mask for Channel 4 interrupt status bits.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk4`]
module"]
#[doc(alias = "hostgrp_hcintmsk4")]
pub type HostgrpHcintmsk4 = crate::Reg<hostgrp_hcintmsk4::HostgrpHcintmsk4Spec>;
#[doc = "This register reflects the mask for Channel 4 interrupt status bits."]
pub mod hostgrp_hcintmsk4;
#[doc = "hostgrp_hctsiz4 (rw) register accessor: Buffer DMA Mode Channel 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz4`]
module"]
#[doc(alias = "hostgrp_hctsiz4")]
pub type HostgrpHctsiz4 = crate::Reg<hostgrp_hctsiz4::HostgrpHctsiz4Spec>;
#[doc = "Buffer DMA Mode Channel 4"]
pub mod hostgrp_hctsiz4;
#[doc = "hostgrp_hcdma4 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma4`]
module"]
#[doc(alias = "hostgrp_hcdma4")]
pub type HostgrpHcdma4 = crate::Reg<hostgrp_hcdma4::HostgrpHcdma4Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma4;
#[doc = "hostgrp_hcdmab4 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab4`]
module"]
#[doc(alias = "hostgrp_hcdmab4")]
pub type HostgrpHcdmab4 = crate::Reg<hostgrp_hcdmab4::HostgrpHcdmab4Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab4;
#[doc = "hostgrp_hcchar5 (rw) register accessor: Channel_number: 5.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar5`]
module"]
#[doc(alias = "hostgrp_hcchar5")]
pub type HostgrpHcchar5 = crate::Reg<hostgrp_hcchar5::HostgrpHcchar5Spec>;
#[doc = "Channel_number: 5."]
pub mod hostgrp_hcchar5;
#[doc = "hostgrp_hcsplt5 (rw) register accessor: Channel_number 5\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt5`]
module"]
#[doc(alias = "hostgrp_hcsplt5")]
pub type HostgrpHcsplt5 = crate::Reg<hostgrp_hcsplt5::HostgrpHcsplt5Spec>;
#[doc = "Channel_number 5"]
pub mod hostgrp_hcsplt5;
#[doc = "hostgrp_hcint5 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint5::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint5`]
module"]
#[doc(alias = "hostgrp_hcint5")]
pub type HostgrpHcint5 = crate::Reg<hostgrp_hcint5::HostgrpHcint5Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint5;
#[doc = "hostgrp_hcintmsk5 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk5`]
module"]
#[doc(alias = "hostgrp_hcintmsk5")]
pub type HostgrpHcintmsk5 = crate::Reg<hostgrp_hcintmsk5::HostgrpHcintmsk5Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk5;
#[doc = "hostgrp_hctsiz5 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz5`]
module"]
#[doc(alias = "hostgrp_hctsiz5")]
pub type HostgrpHctsiz5 = crate::Reg<hostgrp_hctsiz5::HostgrpHctsiz5Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz5;
#[doc = "hostgrp_hcdma5 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma5`]
module"]
#[doc(alias = "hostgrp_hcdma5")]
pub type HostgrpHcdma5 = crate::Reg<hostgrp_hcdma5::HostgrpHcdma5Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma5;
#[doc = "hostgrp_hcdmab5 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab5`]
module"]
#[doc(alias = "hostgrp_hcdmab5")]
pub type HostgrpHcdmab5 = crate::Reg<hostgrp_hcdmab5::HostgrpHcdmab5Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab5;
#[doc = "hostgrp_hcchar6 (rw) register accessor: Host Channel 6 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar6`]
module"]
#[doc(alias = "hostgrp_hcchar6")]
pub type HostgrpHcchar6 = crate::Reg<hostgrp_hcchar6::HostgrpHcchar6Spec>;
#[doc = "Host Channel 6 Characteristics Register"]
pub mod hostgrp_hcchar6;
#[doc = "hostgrp_hcsplt6 (rw) register accessor: Channel_number 6\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt6`]
module"]
#[doc(alias = "hostgrp_hcsplt6")]
pub type HostgrpHcsplt6 = crate::Reg<hostgrp_hcsplt6::HostgrpHcsplt6Spec>;
#[doc = "Channel_number 6"]
pub mod hostgrp_hcsplt6;
#[doc = "hostgrp_hcint6 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint6::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint6`]
module"]
#[doc(alias = "hostgrp_hcint6")]
pub type HostgrpHcint6 = crate::Reg<hostgrp_hcint6::HostgrpHcint6Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint6;
#[doc = "hostgrp_hcintmsk6 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk6`]
module"]
#[doc(alias = "hostgrp_hcintmsk6")]
pub type HostgrpHcintmsk6 = crate::Reg<hostgrp_hcintmsk6::HostgrpHcintmsk6Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk6;
#[doc = "hostgrp_hctsiz6 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz6`]
module"]
#[doc(alias = "hostgrp_hctsiz6")]
pub type HostgrpHctsiz6 = crate::Reg<hostgrp_hctsiz6::HostgrpHctsiz6Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz6;
#[doc = "hostgrp_hcdma6 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma6`]
module"]
#[doc(alias = "hostgrp_hcdma6")]
pub type HostgrpHcdma6 = crate::Reg<hostgrp_hcdma6::HostgrpHcdma6Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma6;
#[doc = "hostgrp_hcdmab6 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab6`]
module"]
#[doc(alias = "hostgrp_hcdmab6")]
pub type HostgrpHcdmab6 = crate::Reg<hostgrp_hcdmab6::HostgrpHcdmab6Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab6;
#[doc = "hostgrp_hcchar7 (rw) register accessor: Host Channel 7 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar7`]
module"]
#[doc(alias = "hostgrp_hcchar7")]
pub type HostgrpHcchar7 = crate::Reg<hostgrp_hcchar7::HostgrpHcchar7Spec>;
#[doc = "Host Channel 7 Characteristics Register"]
pub mod hostgrp_hcchar7;
#[doc = "hostgrp_hcsplt7 (rw) register accessor: Channel_number 7\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt7`]
module"]
#[doc(alias = "hostgrp_hcsplt7")]
pub type HostgrpHcsplt7 = crate::Reg<hostgrp_hcsplt7::HostgrpHcsplt7Spec>;
#[doc = "Channel_number 7"]
pub mod hostgrp_hcsplt7;
#[doc = "hostgrp_hcint7 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint7::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint7`]
module"]
#[doc(alias = "hostgrp_hcint7")]
pub type HostgrpHcint7 = crate::Reg<hostgrp_hcint7::HostgrpHcint7Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint7;
#[doc = "hostgrp_hcintmsk7 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk7`]
module"]
#[doc(alias = "hostgrp_hcintmsk7")]
pub type HostgrpHcintmsk7 = crate::Reg<hostgrp_hcintmsk7::HostgrpHcintmsk7Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk7;
#[doc = "hostgrp_hctsiz7 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz7`]
module"]
#[doc(alias = "hostgrp_hctsiz7")]
pub type HostgrpHctsiz7 = crate::Reg<hostgrp_hctsiz7::HostgrpHctsiz7Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz7;
#[doc = "hostgrp_hcdma7 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma7`]
module"]
#[doc(alias = "hostgrp_hcdma7")]
pub type HostgrpHcdma7 = crate::Reg<hostgrp_hcdma7::HostgrpHcdma7Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma7;
#[doc = "hostgrp_hcdmab7 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab7`]
module"]
#[doc(alias = "hostgrp_hcdmab7")]
pub type HostgrpHcdmab7 = crate::Reg<hostgrp_hcdmab7::HostgrpHcdmab7Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab7;
#[doc = "hostgrp_hcchar8 (rw) register accessor: Host Channel 8 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar8`]
module"]
#[doc(alias = "hostgrp_hcchar8")]
pub type HostgrpHcchar8 = crate::Reg<hostgrp_hcchar8::HostgrpHcchar8Spec>;
#[doc = "Host Channel 8 Characteristics Register"]
pub mod hostgrp_hcchar8;
#[doc = "hostgrp_hcsplt8 (rw) register accessor: Channel_number 8\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt8`]
module"]
#[doc(alias = "hostgrp_hcsplt8")]
pub type HostgrpHcsplt8 = crate::Reg<hostgrp_hcsplt8::HostgrpHcsplt8Spec>;
#[doc = "Channel_number 8"]
pub mod hostgrp_hcsplt8;
#[doc = "hostgrp_hcint8 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint8::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint8`]
module"]
#[doc(alias = "hostgrp_hcint8")]
pub type HostgrpHcint8 = crate::Reg<hostgrp_hcint8::HostgrpHcint8Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint8;
#[doc = "hostgrp_hcintmsk8 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk8`]
module"]
#[doc(alias = "hostgrp_hcintmsk8")]
pub type HostgrpHcintmsk8 = crate::Reg<hostgrp_hcintmsk8::HostgrpHcintmsk8Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk8;
#[doc = "hostgrp_hctsiz8 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz8`]
module"]
#[doc(alias = "hostgrp_hctsiz8")]
pub type HostgrpHctsiz8 = crate::Reg<hostgrp_hctsiz8::HostgrpHctsiz8Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz8;
#[doc = "hostgrp_hcdma8 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma8`]
module"]
#[doc(alias = "hostgrp_hcdma8")]
pub type HostgrpHcdma8 = crate::Reg<hostgrp_hcdma8::HostgrpHcdma8Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma8;
#[doc = "hostgrp_hcdmab8 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab8`]
module"]
#[doc(alias = "hostgrp_hcdmab8")]
pub type HostgrpHcdmab8 = crate::Reg<hostgrp_hcdmab8::HostgrpHcdmab8Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab8;
#[doc = "hostgrp_hcchar9 (rw) register accessor: Host Channel 9 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar9`]
module"]
#[doc(alias = "hostgrp_hcchar9")]
pub type HostgrpHcchar9 = crate::Reg<hostgrp_hcchar9::HostgrpHcchar9Spec>;
#[doc = "Host Channel 9 Characteristics Register"]
pub mod hostgrp_hcchar9;
#[doc = "hostgrp_hcsplt9 (rw) register accessor: Channel_number 9\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt9`]
module"]
#[doc(alias = "hostgrp_hcsplt9")]
pub type HostgrpHcsplt9 = crate::Reg<hostgrp_hcsplt9::HostgrpHcsplt9Spec>;
#[doc = "Channel_number 9"]
pub mod hostgrp_hcsplt9;
#[doc = "hostgrp_hcint9 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint9::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint9`]
module"]
#[doc(alias = "hostgrp_hcint9")]
pub type HostgrpHcint9 = crate::Reg<hostgrp_hcint9::HostgrpHcint9Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint9;
#[doc = "hostgrp_hcintmsk9 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk9`]
module"]
#[doc(alias = "hostgrp_hcintmsk9")]
pub type HostgrpHcintmsk9 = crate::Reg<hostgrp_hcintmsk9::HostgrpHcintmsk9Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk9;
#[doc = "hostgrp_hctsiz9 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz9`]
module"]
#[doc(alias = "hostgrp_hctsiz9")]
pub type HostgrpHctsiz9 = crate::Reg<hostgrp_hctsiz9::HostgrpHctsiz9Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz9;
#[doc = "hostgrp_hcdma9 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma9`]
module"]
#[doc(alias = "hostgrp_hcdma9")]
pub type HostgrpHcdma9 = crate::Reg<hostgrp_hcdma9::HostgrpHcdma9Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma9;
#[doc = "hostgrp_hcdmab9 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab9`]
module"]
#[doc(alias = "hostgrp_hcdmab9")]
pub type HostgrpHcdmab9 = crate::Reg<hostgrp_hcdmab9::HostgrpHcdmab9Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab9;
#[doc = "hostgrp_hcchar10 (rw) register accessor: Host Channel 1 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar10`]
module"]
#[doc(alias = "hostgrp_hcchar10")]
pub type HostgrpHcchar10 = crate::Reg<hostgrp_hcchar10::HostgrpHcchar10Spec>;
#[doc = "Host Channel 1 Characteristics Register"]
pub mod hostgrp_hcchar10;
#[doc = "hostgrp_hcsplt10 (rw) register accessor: Channel_number 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt10`]
module"]
#[doc(alias = "hostgrp_hcsplt10")]
pub type HostgrpHcsplt10 = crate::Reg<hostgrp_hcsplt10::HostgrpHcsplt10Spec>;
#[doc = "Channel_number 1"]
pub mod hostgrp_hcsplt10;
#[doc = "hostgrp_hcint10 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint10::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint10`]
module"]
#[doc(alias = "hostgrp_hcint10")]
pub type HostgrpHcint10 = crate::Reg<hostgrp_hcint10::HostgrpHcint10Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint10;
#[doc = "hostgrp_hcintmsk10 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk10`]
module"]
#[doc(alias = "hostgrp_hcintmsk10")]
pub type HostgrpHcintmsk10 = crate::Reg<hostgrp_hcintmsk10::HostgrpHcintmsk10Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk10;
#[doc = "hostgrp_hctsiz10 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz10`]
module"]
#[doc(alias = "hostgrp_hctsiz10")]
pub type HostgrpHctsiz10 = crate::Reg<hostgrp_hctsiz10::HostgrpHctsiz10Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz10;
#[doc = "hostgrp_hcdma10 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma10`]
module"]
#[doc(alias = "hostgrp_hcdma10")]
pub type HostgrpHcdma10 = crate::Reg<hostgrp_hcdma10::HostgrpHcdma10Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma10;
#[doc = "hostgrp_hcdmab10 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab10`]
module"]
#[doc(alias = "hostgrp_hcdmab10")]
pub type HostgrpHcdmab10 = crate::Reg<hostgrp_hcdmab10::HostgrpHcdmab10Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab10;
#[doc = "hostgrp_hcchar11 (rw) register accessor: Host Channel 11 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar11`]
module"]
#[doc(alias = "hostgrp_hcchar11")]
pub type HostgrpHcchar11 = crate::Reg<hostgrp_hcchar11::HostgrpHcchar11Spec>;
#[doc = "Host Channel 11 Characteristics Register"]
pub mod hostgrp_hcchar11;
#[doc = "hostgrp_HCSPLT11 (rw) register accessor: Channel number 11.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt11`]
module"]
#[doc(alias = "hostgrp_HCSPLT11")]
pub type HostgrpHcsplt11 = crate::Reg<hostgrp_hcsplt11::HostgrpHcsplt11Spec>;
#[doc = "Channel number 11."]
pub mod hostgrp_hcsplt11;
#[doc = "hostgrp_hcint11 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint11::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint11`]
module"]
#[doc(alias = "hostgrp_hcint11")]
pub type HostgrpHcint11 = crate::Reg<hostgrp_hcint11::HostgrpHcint11Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint11;
#[doc = "hostgrp_hcintmsk11 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk11`]
module"]
#[doc(alias = "hostgrp_hcintmsk11")]
pub type HostgrpHcintmsk11 = crate::Reg<hostgrp_hcintmsk11::HostgrpHcintmsk11Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk11;
#[doc = "hostgrp_hctsiz11 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz11`]
module"]
#[doc(alias = "hostgrp_hctsiz11")]
pub type HostgrpHctsiz11 = crate::Reg<hostgrp_hctsiz11::HostgrpHctsiz11Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz11;
#[doc = "hostgrp_hcdma11 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma11`]
module"]
#[doc(alias = "hostgrp_hcdma11")]
pub type HostgrpHcdma11 = crate::Reg<hostgrp_hcdma11::HostgrpHcdma11Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma11;
#[doc = "hostgrp_hcdmab11 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab11`]
module"]
#[doc(alias = "hostgrp_hcdmab11")]
pub type HostgrpHcdmab11 = crate::Reg<hostgrp_hcdmab11::HostgrpHcdmab11Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab11;
#[doc = "hostgrp_hcchar12 (rw) register accessor: Host Channel 1 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar12`]
module"]
#[doc(alias = "hostgrp_hcchar12")]
pub type HostgrpHcchar12 = crate::Reg<hostgrp_hcchar12::HostgrpHcchar12Spec>;
#[doc = "Host Channel 1 Characteristics Register"]
pub mod hostgrp_hcchar12;
#[doc = "hostgrp_hcsplt12 (rw) register accessor: Channel_number 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt12`]
module"]
#[doc(alias = "hostgrp_hcsplt12")]
pub type HostgrpHcsplt12 = crate::Reg<hostgrp_hcsplt12::HostgrpHcsplt12Spec>;
#[doc = "Channel_number 1"]
pub mod hostgrp_hcsplt12;
#[doc = "hostgrp_hcint12 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint12::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint12`]
module"]
#[doc(alias = "hostgrp_hcint12")]
pub type HostgrpHcint12 = crate::Reg<hostgrp_hcint12::HostgrpHcint12Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint12;
#[doc = "hostgrp_hcintmsk12 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk12`]
module"]
#[doc(alias = "hostgrp_hcintmsk12")]
pub type HostgrpHcintmsk12 = crate::Reg<hostgrp_hcintmsk12::HostgrpHcintmsk12Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk12;
#[doc = "hostgrp_hctsiz12 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz12`]
module"]
#[doc(alias = "hostgrp_hctsiz12")]
pub type HostgrpHctsiz12 = crate::Reg<hostgrp_hctsiz12::HostgrpHctsiz12Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz12;
#[doc = "hostgrp_hcdma12 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma12`]
module"]
#[doc(alias = "hostgrp_hcdma12")]
pub type HostgrpHcdma12 = crate::Reg<hostgrp_hcdma12::HostgrpHcdma12Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma12;
#[doc = "hostgrp_hcdmab12 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab12`]
module"]
#[doc(alias = "hostgrp_hcdmab12")]
pub type HostgrpHcdmab12 = crate::Reg<hostgrp_hcdmab12::HostgrpHcdmab12Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab12;
#[doc = "hostgrp_hcchar13 (rw) register accessor: Host Channel 13 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar13`]
module"]
#[doc(alias = "hostgrp_hcchar13")]
pub type HostgrpHcchar13 = crate::Reg<hostgrp_hcchar13::HostgrpHcchar13Spec>;
#[doc = "Host Channel 13 Characteristics Register"]
pub mod hostgrp_hcchar13;
#[doc = "hostgrp_hcsplt13 (rw) register accessor: Channel_number 13.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt13`]
module"]
#[doc(alias = "hostgrp_hcsplt13")]
pub type HostgrpHcsplt13 = crate::Reg<hostgrp_hcsplt13::HostgrpHcsplt13Spec>;
#[doc = "Channel_number 13."]
pub mod hostgrp_hcsplt13;
#[doc = "hostgrp_hcint13 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint13::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint13`]
module"]
#[doc(alias = "hostgrp_hcint13")]
pub type HostgrpHcint13 = crate::Reg<hostgrp_hcint13::HostgrpHcint13Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint13;
#[doc = "hostgrp_hcintmsk13 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk13`]
module"]
#[doc(alias = "hostgrp_hcintmsk13")]
pub type HostgrpHcintmsk13 = crate::Reg<hostgrp_hcintmsk13::HostgrpHcintmsk13Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk13;
#[doc = "hostgrp_hctsiz13 (rw) register accessor: Buffer DMA Mode\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz13`]
module"]
#[doc(alias = "hostgrp_hctsiz13")]
pub type HostgrpHctsiz13 = crate::Reg<hostgrp_hctsiz13::HostgrpHctsiz13Spec>;
#[doc = "Buffer DMA Mode"]
pub mod hostgrp_hctsiz13;
#[doc = "hostgrp_hcdma13 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma13`]
module"]
#[doc(alias = "hostgrp_hcdma13")]
pub type HostgrpHcdma13 = crate::Reg<hostgrp_hcdma13::HostgrpHcdma13Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma13;
#[doc = "hostgrp_hcdmab13 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab13`]
module"]
#[doc(alias = "hostgrp_hcdmab13")]
pub type HostgrpHcdmab13 = crate::Reg<hostgrp_hcdmab13::HostgrpHcdmab13Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab13;
#[doc = "hostgrp_hcchar14 (rw) register accessor: Host Channel 1 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar14`]
module"]
#[doc(alias = "hostgrp_hcchar14")]
pub type HostgrpHcchar14 = crate::Reg<hostgrp_hcchar14::HostgrpHcchar14Spec>;
#[doc = "Host Channel 1 Characteristics Register"]
pub mod hostgrp_hcchar14;
#[doc = "hostgrp_hcsplt14 (rw) register accessor: Channel_number 14\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt14`]
module"]
#[doc(alias = "hostgrp_hcsplt14")]
pub type HostgrpHcsplt14 = crate::Reg<hostgrp_hcsplt14::HostgrpHcsplt14Spec>;
#[doc = "Channel_number 14"]
pub mod hostgrp_hcsplt14;
#[doc = "hostgrp_hcint14 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint14::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint14`]
module"]
#[doc(alias = "hostgrp_hcint14")]
pub type HostgrpHcint14 = crate::Reg<hostgrp_hcint14::HostgrpHcint14Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint14;
#[doc = "hostgrp_hcintmsk14 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk14`]
module"]
#[doc(alias = "hostgrp_hcintmsk14")]
pub type HostgrpHcintmsk14 = crate::Reg<hostgrp_hcintmsk14::HostgrpHcintmsk14Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk14;
#[doc = "hostgrp_hctsiz14 (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz14`]
module"]
#[doc(alias = "hostgrp_hctsiz14")]
pub type HostgrpHctsiz14 = crate::Reg<hostgrp_hctsiz14::HostgrpHctsiz14Spec>;
#[doc = ""]
pub mod hostgrp_hctsiz14;
#[doc = "hostgrp_hcdma14 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma14`]
module"]
#[doc(alias = "hostgrp_hcdma14")]
pub type HostgrpHcdma14 = crate::Reg<hostgrp_hcdma14::HostgrpHcdma14Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma14;
#[doc = "hostgrp_hcdmab14 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab14`]
module"]
#[doc(alias = "hostgrp_hcdmab14")]
pub type HostgrpHcdmab14 = crate::Reg<hostgrp_hcdmab14::HostgrpHcdmab14Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab14;
#[doc = "hostgrp_hcchar15 (rw) register accessor: Host Channel 15 Characteristics Register\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcchar15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcchar15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcchar15`]
module"]
#[doc(alias = "hostgrp_hcchar15")]
pub type HostgrpHcchar15 = crate::Reg<hostgrp_hcchar15::HostgrpHcchar15Spec>;
#[doc = "Host Channel 15 Characteristics Register"]
pub mod hostgrp_hcchar15;
#[doc = "hostgrp_hcsplt15 (rw) register accessor: Channel_number 15.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcsplt15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcsplt15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcsplt15`]
module"]
#[doc(alias = "hostgrp_hcsplt15")]
pub type HostgrpHcsplt15 = crate::Reg<hostgrp_hcsplt15::HostgrpHcsplt15Spec>;
#[doc = "Channel_number 15."]
pub mod hostgrp_hcsplt15;
#[doc = "hostgrp_hcint15 (r) register accessor: This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcint15::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcint15`]
module"]
#[doc(alias = "hostgrp_hcint15")]
pub type HostgrpHcint15 = crate::Reg<hostgrp_hcint15::HostgrpHcint15Spec>;
#[doc = "This register indicates the status of a channel with respect to USB- and AHB-related events. The application must read this register when the Host Channels Interrupt bit of the Core Interrupt register (GINTSTS.HChInt) is set. Before the application can read this register, it must first read the Host All Channels Interrupt (HAINT) register to get the exact channel number for the Host Channel-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the HAINT and GINTSTS registers."]
pub mod hostgrp_hcint15;
#[doc = "hostgrp_hcintmsk15 (rw) register accessor: This register reflects the mask for each channel status described in the previous section.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcintmsk15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcintmsk15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcintmsk15`]
module"]
#[doc(alias = "hostgrp_hcintmsk15")]
pub type HostgrpHcintmsk15 = crate::Reg<hostgrp_hcintmsk15::HostgrpHcintmsk15Spec>;
#[doc = "This register reflects the mask for each channel status described in the previous section."]
pub mod hostgrp_hcintmsk15;
#[doc = "hostgrp_hctsiz15 (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hctsiz15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hctsiz15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hctsiz15`]
module"]
#[doc(alias = "hostgrp_hctsiz15")]
pub type HostgrpHctsiz15 = crate::Reg<hostgrp_hctsiz15::HostgrpHctsiz15Spec>;
#[doc = ""]
pub mod hostgrp_hctsiz15;
#[doc = "hostgrp_hcdma15 (rw) register accessor: This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdma15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdma15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdma15`]
module"]
#[doc(alias = "hostgrp_hcdma15")]
pub type HostgrpHcdma15 = crate::Reg<hostgrp_hcdma15::HostgrpHcdma15Spec>;
#[doc = "This register is used by the OTG host in the internal DMA mode to maintain the current buffer pointer for IN/OUT transactions. The starting DMA address must be DWORD-aligned."]
pub mod hostgrp_hcdma15;
#[doc = "hostgrp_hcdmab15 (rw) register accessor: These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`hostgrp_hcdmab15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`hostgrp_hcdmab15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@hostgrp_hcdmab15`]
module"]
#[doc(alias = "hostgrp_hcdmab15")]
pub type HostgrpHcdmab15 = crate::Reg<hostgrp_hcdmab15::HostgrpHcdmab15Spec>;
#[doc = "These registers are present only in case of Scatter/Gather DMA. These registers are implemented in RAM instead of flop-based implementation. Holds the current buffer address. This register is updated as and when the data transfer for the corresponding end point is in progress. This register is present only in Scatter/Gather DMA mode. Otherwise this field is reserved."]
pub mod hostgrp_hcdmab15;
#[doc = "devgrp_dcfg (rw) register accessor: This register configures the core in Device mode after power-on or after certain control commands or enumeration. Do not make changes to this register after initial programming.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dcfg::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dcfg::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dcfg`]
module"]
#[doc(alias = "devgrp_dcfg")]
pub type DevgrpDcfg = crate::Reg<devgrp_dcfg::DevgrpDcfgSpec>;
#[doc = "This register configures the core in Device mode after power-on or after certain control commands or enumeration. Do not make changes to this register after initial programming."]
pub mod devgrp_dcfg;
#[doc = "devgrp_dctl (rw) register accessor: \n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dctl`]
module"]
#[doc(alias = "devgrp_dctl")]
pub type DevgrpDctl = crate::Reg<devgrp_dctl::DevgrpDctlSpec>;
#[doc = ""]
pub mod devgrp_dctl;
#[doc = "devgrp_dsts (r) register accessor: This register indicates the status of the core with respect to USB-related events. It must be read on interrupts from Device All Interrupts (DAINT) register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dsts::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dsts`]
module"]
#[doc(alias = "devgrp_dsts")]
pub type DevgrpDsts = crate::Reg<devgrp_dsts::DevgrpDstsSpec>;
#[doc = "This register indicates the status of the core with respect to USB-related events. It must be read on interrupts from Device All Interrupts (DAINT) register."]
pub mod devgrp_dsts;
#[doc = "devgrp_diepmsk (rw) register accessor: This register works with each of the Device IN Endpoint Interrupt (DIEPINTn) registers for all endpoints to generate an interrupt per IN endpoint. The IN endpoint interrupt for a specific status in the DIEPINTn register can be masked by writing to the corresponding bit in this register. Status bits are masked by default.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepmsk`]
module"]
#[doc(alias = "devgrp_diepmsk")]
pub type DevgrpDiepmsk = crate::Reg<devgrp_diepmsk::DevgrpDiepmskSpec>;
#[doc = "This register works with each of the Device IN Endpoint Interrupt (DIEPINTn) registers for all endpoints to generate an interrupt per IN endpoint. The IN endpoint interrupt for a specific status in the DIEPINTn register can be masked by writing to the corresponding bit in this register. Status bits are masked by default."]
pub mod devgrp_diepmsk;
#[doc = "devgrp_doepmsk (rw) register accessor: This register works with each of the Device OUT Endpoint Interrupt (DOEPINTn) registers for all endpoints to generate an interrupt per OUT endpoint. The OUT endpoint interrupt for a specific status in the DOEPINTn register can be masked by writing into the corresponding bit in this register. Status bits are masked by default\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepmsk`]
module"]
#[doc(alias = "devgrp_doepmsk")]
pub type DevgrpDoepmsk = crate::Reg<devgrp_doepmsk::DevgrpDoepmskSpec>;
#[doc = "This register works with each of the Device OUT Endpoint Interrupt (DOEPINTn) registers for all endpoints to generate an interrupt per OUT endpoint. The OUT endpoint interrupt for a specific status in the DOEPINTn register can be masked by writing into the corresponding bit in this register. Status bits are masked by default"]
pub mod devgrp_doepmsk;
#[doc = "devgrp_daint (r) register accessor: When a significant event occurs on an endpoint, a Device All Endpoints Interrupt register interrupts the application using the Device OUT Endpoints Interrupt bit or Device IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively). This is shown in Figure 5-2. There is one interrupt bit per endpoint, up to a maximum of 16 bits for OUT endpoints and 16 bits for IN endpoints. for a bidirectional endpoint, the corresponding IN and OUT interrupt bits are used. Bits in this register are set and cleared when the application sets and clears bits in the corresponding Device Endpoint-n Interrupt register (DIEPINTn/DOEPINTn).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_daint::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_daint`]
module"]
#[doc(alias = "devgrp_daint")]
pub type DevgrpDaint = crate::Reg<devgrp_daint::DevgrpDaintSpec>;
#[doc = "When a significant event occurs on an endpoint, a Device All Endpoints Interrupt register interrupts the application using the Device OUT Endpoints Interrupt bit or Device IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively). This is shown in Figure 5-2. There is one interrupt bit per endpoint, up to a maximum of 16 bits for OUT endpoints and 16 bits for IN endpoints. for a bidirectional endpoint, the corresponding IN and OUT interrupt bits are used. Bits in this register are set and cleared when the application sets and clears bits in the corresponding Device Endpoint-n Interrupt register (DIEPINTn/DOEPINTn)."]
pub mod devgrp_daint;
#[doc = "devgrp_daintmsk (rw) register accessor: The Device Endpoint Interrupt Mask register works with the Device Endpoint Interrupt register to interrupt the application when an event occurs on a device endpoint. However, the Device All Endpoints Interrupt (DAINT) register bit corresponding to that interrupt is still set.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_daintmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_daintmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_daintmsk`]
module"]
#[doc(alias = "devgrp_daintmsk")]
pub type DevgrpDaintmsk = crate::Reg<devgrp_daintmsk::DevgrpDaintmskSpec>;
#[doc = "The Device Endpoint Interrupt Mask register works with the Device Endpoint Interrupt register to interrupt the application when an event occurs on a device endpoint. However, the Device All Endpoints Interrupt (DAINT) register bit corresponding to that interrupt is still set."]
pub mod devgrp_daintmsk;
#[doc = "devgrp_dvbusdis (rw) register accessor: This register specifies the VBUS discharge time after VBUS pulsing during SRP.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dvbusdis::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dvbusdis::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dvbusdis`]
module"]
#[doc(alias = "devgrp_dvbusdis")]
pub type DevgrpDvbusdis = crate::Reg<devgrp_dvbusdis::DevgrpDvbusdisSpec>;
#[doc = "This register specifies the VBUS discharge time after VBUS pulsing during SRP."]
pub mod devgrp_dvbusdis;
#[doc = "devgrp_dvbuspulse (rw) register accessor: This register specifies the VBUS pulsing time during SRP.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dvbuspulse::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dvbuspulse::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dvbuspulse`]
module"]
#[doc(alias = "devgrp_dvbuspulse")]
pub type DevgrpDvbuspulse = crate::Reg<devgrp_dvbuspulse::DevgrpDvbuspulseSpec>;
#[doc = "This register specifies the VBUS pulsing time during SRP."]
pub mod devgrp_dvbuspulse;
#[doc = "devgrp_dthrctl (rw) register accessor: Thresholding is not supported in Slave mode and so this register must not be programmed in Slave mode. for threshold support, the AHB must be run at 60 MHz or higher.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dthrctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dthrctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dthrctl`]
module"]
#[doc(alias = "devgrp_dthrctl")]
pub type DevgrpDthrctl = crate::Reg<devgrp_dthrctl::DevgrpDthrctlSpec>;
#[doc = "Thresholding is not supported in Slave mode and so this register must not be programmed in Slave mode. for threshold support, the AHB must be run at 60 MHz or higher."]
pub mod devgrp_dthrctl;
#[doc = "devgrp_diepempmsk (rw) register accessor: This register is used to control the IN endpoint FIFO empty interrupt generation (DIEPINTn.TxfEmp).\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepempmsk::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepempmsk::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepempmsk`]
module"]
#[doc(alias = "devgrp_diepempmsk")]
pub type DevgrpDiepempmsk = crate::Reg<devgrp_diepempmsk::DevgrpDiepempmskSpec>;
#[doc = "This register is used to control the IN endpoint FIFO empty interrupt generation (DIEPINTn.TxfEmp)."]
pub mod devgrp_diepempmsk;
#[doc = "devgrp_diepctl0 (rw) register accessor: This register covers Device Control IN Endpoint 0.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl0`]
module"]
#[doc(alias = "devgrp_diepctl0")]
pub type DevgrpDiepctl0 = crate::Reg<devgrp_diepctl0::DevgrpDiepctl0Spec>;
#[doc = "This register covers Device Control IN Endpoint 0."]
pub mod devgrp_diepctl0;
#[doc = "devgrp_diepint0 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint0`]
module"]
#[doc(alias = "devgrp_diepint0")]
pub type DevgrpDiepint0 = crate::Reg<devgrp_diepint0::DevgrpDiepint0Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint0;
#[doc = "devgrp_dieptsiz0 (rw) register accessor: The application must modify this register before enabling endpoint 0. Once endpoint 0 is enabled using Endpoint Enable bit of the Device Control Endpoint 0 Control registers (DIEPCTL0.EPEna/DOEPCTL0.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit. Nonzero endpoints use the registers for endpoints 1 to 15. When Scatter/Gather DMA mode is enabled, this register must not be programmed by the application. If the application reads this register when Scatter/Gather DMA mode is enabled, the core returns all zeros.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz0`]
module"]
#[doc(alias = "devgrp_dieptsiz0")]
pub type DevgrpDieptsiz0 = crate::Reg<devgrp_dieptsiz0::DevgrpDieptsiz0Spec>;
#[doc = "The application must modify this register before enabling endpoint 0. Once endpoint 0 is enabled using Endpoint Enable bit of the Device Control Endpoint 0 Control registers (DIEPCTL0.EPEna/DOEPCTL0.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit. Nonzero endpoints use the registers for endpoints 1 to 15. When Scatter/Gather DMA mode is enabled, this register must not be programmed by the application. If the application reads this register when Scatter/Gather DMA mode is enabled, the core returns all zeros."]
pub mod devgrp_dieptsiz0;
#[doc = "devgrp_diepdma0 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma0::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma0`]
module"]
#[doc(alias = "devgrp_diepdma0")]
pub type DevgrpDiepdma0 = crate::Reg<devgrp_diepdma0::DevgrpDiepdma0Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma0;
#[doc = "devgrp_dtxfsts0 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts0`]
module"]
#[doc(alias = "devgrp_dtxfsts0")]
pub type DevgrpDtxfsts0 = crate::Reg<devgrp_dtxfsts0::DevgrpDtxfsts0Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts0;
#[doc = "devgrp_diepdmab0 (r) register accessor: Endpoint 16.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab0`]
module"]
#[doc(alias = "devgrp_diepdmab0")]
pub type DevgrpDiepdmab0 = crate::Reg<devgrp_diepdmab0::DevgrpDiepdmab0Spec>;
#[doc = "Endpoint 16."]
pub mod devgrp_diepdmab0;
#[doc = "devgrp_diepctl1 (rw) register accessor: Endpoint_number: 1\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl1`]
module"]
#[doc(alias = "devgrp_diepctl1")]
pub type DevgrpDiepctl1 = crate::Reg<devgrp_diepctl1::DevgrpDiepctl1Spec>;
#[doc = "Endpoint_number: 1"]
pub mod devgrp_diepctl1;
#[doc = "devgrp_diepint1 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint1`]
module"]
#[doc(alias = "devgrp_diepint1")]
pub type DevgrpDiepint1 = crate::Reg<devgrp_diepint1::DevgrpDiepint1Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint1;
#[doc = "devgrp_dieptsiz1 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz1`]
module"]
#[doc(alias = "devgrp_dieptsiz1")]
pub type DevgrpDieptsiz1 = crate::Reg<devgrp_dieptsiz1::DevgrpDieptsiz1Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz1;
#[doc = "devgrp_diepdma1 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma1::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma1`]
module"]
#[doc(alias = "devgrp_diepdma1")]
pub type DevgrpDiepdma1 = crate::Reg<devgrp_diepdma1::DevgrpDiepdma1Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma1;
#[doc = "devgrp_dtxfsts1 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts1`]
module"]
#[doc(alias = "devgrp_dtxfsts1")]
pub type DevgrpDtxfsts1 = crate::Reg<devgrp_dtxfsts1::DevgrpDtxfsts1Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts1;
#[doc = "devgrp_diepdmab1 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab1`]
module"]
#[doc(alias = "devgrp_diepdmab1")]
pub type DevgrpDiepdmab1 = crate::Reg<devgrp_diepdmab1::DevgrpDiepdmab1Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab1;
#[doc = "devgrp_diepctl2 (rw) register accessor: Endpoint_number: 2\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl2`]
module"]
#[doc(alias = "devgrp_diepctl2")]
pub type DevgrpDiepctl2 = crate::Reg<devgrp_diepctl2::DevgrpDiepctl2Spec>;
#[doc = "Endpoint_number: 2"]
pub mod devgrp_diepctl2;
#[doc = "devgrp_diepint2 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint2`]
module"]
#[doc(alias = "devgrp_diepint2")]
pub type DevgrpDiepint2 = crate::Reg<devgrp_diepint2::DevgrpDiepint2Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint2;
#[doc = "devgrp_dieptsiz2 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz2`]
module"]
#[doc(alias = "devgrp_dieptsiz2")]
pub type DevgrpDieptsiz2 = crate::Reg<devgrp_dieptsiz2::DevgrpDieptsiz2Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz2;
#[doc = "devgrp_diepdma2 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma2::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma2`]
module"]
#[doc(alias = "devgrp_diepdma2")]
pub type DevgrpDiepdma2 = crate::Reg<devgrp_diepdma2::DevgrpDiepdma2Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma2;
#[doc = "devgrp_DTXFSTS2 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts2`]
module"]
#[doc(alias = "devgrp_DTXFSTS2")]
pub type DevgrpDtxfsts2 = crate::Reg<devgrp_dtxfsts2::DevgrpDtxfsts2Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts2;
#[doc = "devgrp_diepdmab2 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab2`]
module"]
#[doc(alias = "devgrp_diepdmab2")]
pub type DevgrpDiepdmab2 = crate::Reg<devgrp_diepdmab2::DevgrpDiepdmab2Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab2;
#[doc = "devgrp_diepctl3 (rw) register accessor: Endpoint_number: 3\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl3`]
module"]
#[doc(alias = "devgrp_diepctl3")]
pub type DevgrpDiepctl3 = crate::Reg<devgrp_diepctl3::DevgrpDiepctl3Spec>;
#[doc = "Endpoint_number: 3"]
pub mod devgrp_diepctl3;
#[doc = "devgrp_diepint3 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint3`]
module"]
#[doc(alias = "devgrp_diepint3")]
pub type DevgrpDiepint3 = crate::Reg<devgrp_diepint3::DevgrpDiepint3Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint3;
#[doc = "devgrp_dieptsiz3 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz3`]
module"]
#[doc(alias = "devgrp_dieptsiz3")]
pub type DevgrpDieptsiz3 = crate::Reg<devgrp_dieptsiz3::DevgrpDieptsiz3Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz3;
#[doc = "devgrp_diepdma3 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma3::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma3`]
module"]
#[doc(alias = "devgrp_diepdma3")]
pub type DevgrpDiepdma3 = crate::Reg<devgrp_diepdma3::DevgrpDiepdma3Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma3;
#[doc = "devgrp_dtxfsts3 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts3`]
module"]
#[doc(alias = "devgrp_dtxfsts3")]
pub type DevgrpDtxfsts3 = crate::Reg<devgrp_dtxfsts3::DevgrpDtxfsts3Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts3;
#[doc = "devgrp_diepdmab3 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab3`]
module"]
#[doc(alias = "devgrp_diepdmab3")]
pub type DevgrpDiepdmab3 = crate::Reg<devgrp_diepdmab3::DevgrpDiepdmab3Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab3;
#[doc = "devgrp_diepctl4 (rw) register accessor: Endpoint_number: 4\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl4`]
module"]
#[doc(alias = "devgrp_diepctl4")]
pub type DevgrpDiepctl4 = crate::Reg<devgrp_diepctl4::DevgrpDiepctl4Spec>;
#[doc = "Endpoint_number: 4"]
pub mod devgrp_diepctl4;
#[doc = "devgrp_diepint4 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint4`]
module"]
#[doc(alias = "devgrp_diepint4")]
pub type DevgrpDiepint4 = crate::Reg<devgrp_diepint4::DevgrpDiepint4Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint4;
#[doc = "devgrp_dieptsiz4 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz4`]
module"]
#[doc(alias = "devgrp_dieptsiz4")]
pub type DevgrpDieptsiz4 = crate::Reg<devgrp_dieptsiz4::DevgrpDieptsiz4Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz4;
#[doc = "devgrp_diepdma4 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma4::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma4`]
module"]
#[doc(alias = "devgrp_diepdma4")]
pub type DevgrpDiepdma4 = crate::Reg<devgrp_diepdma4::DevgrpDiepdma4Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma4;
#[doc = "devgrp_dtxfsts4 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts4`]
module"]
#[doc(alias = "devgrp_dtxfsts4")]
pub type DevgrpDtxfsts4 = crate::Reg<devgrp_dtxfsts4::DevgrpDtxfsts4Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts4;
#[doc = "devgrp_diepdmab4 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab4`]
module"]
#[doc(alias = "devgrp_diepdmab4")]
pub type DevgrpDiepdmab4 = crate::Reg<devgrp_diepdmab4::DevgrpDiepdmab4Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab4;
#[doc = "devgrp_diepctl5 (rw) register accessor: Endpoint_number: 5\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl5`]
module"]
#[doc(alias = "devgrp_diepctl5")]
pub type DevgrpDiepctl5 = crate::Reg<devgrp_diepctl5::DevgrpDiepctl5Spec>;
#[doc = "Endpoint_number: 5"]
pub mod devgrp_diepctl5;
#[doc = "devgrp_diepint5 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint5::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint5`]
module"]
#[doc(alias = "devgrp_diepint5")]
pub type DevgrpDiepint5 = crate::Reg<devgrp_diepint5::DevgrpDiepint5Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint5;
#[doc = "devgrp_dieptsiz5 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz5`]
module"]
#[doc(alias = "devgrp_dieptsiz5")]
pub type DevgrpDieptsiz5 = crate::Reg<devgrp_dieptsiz5::DevgrpDieptsiz5Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz5;
#[doc = "devgrp_diepdma5 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma5::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma5`]
module"]
#[doc(alias = "devgrp_diepdma5")]
pub type DevgrpDiepdma5 = crate::Reg<devgrp_diepdma5::DevgrpDiepdma5Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma5;
#[doc = "devgrp_dtxfsts5 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts5::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts5`]
module"]
#[doc(alias = "devgrp_dtxfsts5")]
pub type DevgrpDtxfsts5 = crate::Reg<devgrp_dtxfsts5::DevgrpDtxfsts5Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts5;
#[doc = "devgrp_diepdmab5 (r) register accessor: Device IN Endpoint 1 Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab5::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab5`]
module"]
#[doc(alias = "devgrp_diepdmab5")]
pub type DevgrpDiepdmab5 = crate::Reg<devgrp_diepdmab5::DevgrpDiepdmab5Spec>;
#[doc = "Device IN Endpoint 1 Buffer Address."]
pub mod devgrp_diepdmab5;
#[doc = "devgrp_diepctl6 (rw) register accessor: Endpoint_number: 6\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl6`]
module"]
#[doc(alias = "devgrp_diepctl6")]
pub type DevgrpDiepctl6 = crate::Reg<devgrp_diepctl6::DevgrpDiepctl6Spec>;
#[doc = "Endpoint_number: 6"]
pub mod devgrp_diepctl6;
#[doc = "devgrp_diepint6 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint6::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint6`]
module"]
#[doc(alias = "devgrp_diepint6")]
pub type DevgrpDiepint6 = crate::Reg<devgrp_diepint6::DevgrpDiepint6Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint6;
#[doc = "devgrp_dieptsiz6 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz6`]
module"]
#[doc(alias = "devgrp_dieptsiz6")]
pub type DevgrpDieptsiz6 = crate::Reg<devgrp_dieptsiz6::DevgrpDieptsiz6Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz6;
#[doc = "devgrp_diepdma6 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma6::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma6`]
module"]
#[doc(alias = "devgrp_diepdma6")]
pub type DevgrpDiepdma6 = crate::Reg<devgrp_diepdma6::DevgrpDiepdma6Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma6;
#[doc = "devgrp_dtxfsts6 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts6::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts6`]
module"]
#[doc(alias = "devgrp_dtxfsts6")]
pub type DevgrpDtxfsts6 = crate::Reg<devgrp_dtxfsts6::DevgrpDtxfsts6Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts6;
#[doc = "devgrp_diepdmab6 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab6::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab6`]
module"]
#[doc(alias = "devgrp_diepdmab6")]
pub type DevgrpDiepdmab6 = crate::Reg<devgrp_diepdmab6::DevgrpDiepdmab6Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab6;
#[doc = "devgrp_diepctl7 (rw) register accessor: Endpoint_number: 7\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl7`]
module"]
#[doc(alias = "devgrp_diepctl7")]
pub type DevgrpDiepctl7 = crate::Reg<devgrp_diepctl7::DevgrpDiepctl7Spec>;
#[doc = "Endpoint_number: 7"]
pub mod devgrp_diepctl7;
#[doc = "devgrp_diepint7 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint7::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint7`]
module"]
#[doc(alias = "devgrp_diepint7")]
pub type DevgrpDiepint7 = crate::Reg<devgrp_diepint7::DevgrpDiepint7Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint7;
#[doc = "devgrp_dieptsiz7 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz7`]
module"]
#[doc(alias = "devgrp_dieptsiz7")]
pub type DevgrpDieptsiz7 = crate::Reg<devgrp_dieptsiz7::DevgrpDieptsiz7Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz7;
#[doc = "devgrp_diepdma7 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma7::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma7`]
module"]
#[doc(alias = "devgrp_diepdma7")]
pub type DevgrpDiepdma7 = crate::Reg<devgrp_diepdma7::DevgrpDiepdma7Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma7;
#[doc = "devgrp_dtxfsts7 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts7::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts7`]
module"]
#[doc(alias = "devgrp_dtxfsts7")]
pub type DevgrpDtxfsts7 = crate::Reg<devgrp_dtxfsts7::DevgrpDtxfsts7Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts7;
#[doc = "devgrp_diepdmab7 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab7::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab7`]
module"]
#[doc(alias = "devgrp_diepdmab7")]
pub type DevgrpDiepdmab7 = crate::Reg<devgrp_diepdmab7::DevgrpDiepdmab7Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab7;
#[doc = "devgrp_diepctl8 (rw) register accessor: Endpoint_number: 8\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl8`]
module"]
#[doc(alias = "devgrp_diepctl8")]
pub type DevgrpDiepctl8 = crate::Reg<devgrp_diepctl8::DevgrpDiepctl8Spec>;
#[doc = "Endpoint_number: 8"]
pub mod devgrp_diepctl8;
#[doc = "devgrp_diepint8 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint8::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint8`]
module"]
#[doc(alias = "devgrp_diepint8")]
pub type DevgrpDiepint8 = crate::Reg<devgrp_diepint8::DevgrpDiepint8Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint8;
#[doc = "devgrp_dieptsiz8 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz8`]
module"]
#[doc(alias = "devgrp_dieptsiz8")]
pub type DevgrpDieptsiz8 = crate::Reg<devgrp_dieptsiz8::DevgrpDieptsiz8Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz8;
#[doc = "devgrp_diepdma8 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma8::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma8`]
module"]
#[doc(alias = "devgrp_diepdma8")]
pub type DevgrpDiepdma8 = crate::Reg<devgrp_diepdma8::DevgrpDiepdma8Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma8;
#[doc = "devgrp_dtxfsts8 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts8::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts8`]
module"]
#[doc(alias = "devgrp_dtxfsts8")]
pub type DevgrpDtxfsts8 = crate::Reg<devgrp_dtxfsts8::DevgrpDtxfsts8Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts8;
#[doc = "devgrp_diepdmab8 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab8::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab8`]
module"]
#[doc(alias = "devgrp_diepdmab8")]
pub type DevgrpDiepdmab8 = crate::Reg<devgrp_diepdmab8::DevgrpDiepdmab8Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab8;
#[doc = "devgrp_diepctl9 (rw) register accessor: Endpoint_number: 9\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl9`]
module"]
#[doc(alias = "devgrp_diepctl9")]
pub type DevgrpDiepctl9 = crate::Reg<devgrp_diepctl9::DevgrpDiepctl9Spec>;
#[doc = "Endpoint_number: 9"]
pub mod devgrp_diepctl9;
#[doc = "devgrp_diepint9 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint9::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint9`]
module"]
#[doc(alias = "devgrp_diepint9")]
pub type DevgrpDiepint9 = crate::Reg<devgrp_diepint9::DevgrpDiepint9Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint9;
#[doc = "devgrp_dieptsiz9 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz9`]
module"]
#[doc(alias = "devgrp_dieptsiz9")]
pub type DevgrpDieptsiz9 = crate::Reg<devgrp_dieptsiz9::DevgrpDieptsiz9Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz9;
#[doc = "devgrp_diepdma9 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma9::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma9`]
module"]
#[doc(alias = "devgrp_diepdma9")]
pub type DevgrpDiepdma9 = crate::Reg<devgrp_diepdma9::DevgrpDiepdma9Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma9;
#[doc = "devgrp_dtxfsts9 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts9::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts9`]
module"]
#[doc(alias = "devgrp_dtxfsts9")]
pub type DevgrpDtxfsts9 = crate::Reg<devgrp_dtxfsts9::DevgrpDtxfsts9Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts9;
#[doc = "devgrp_diepdmab9 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab9::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab9`]
module"]
#[doc(alias = "devgrp_diepdmab9")]
pub type DevgrpDiepdmab9 = crate::Reg<devgrp_diepdmab9::DevgrpDiepdmab9Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab9;
#[doc = "devgrp_diepctl10 (rw) register accessor: Endpoint_number: 10\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl10`]
module"]
#[doc(alias = "devgrp_diepctl10")]
pub type DevgrpDiepctl10 = crate::Reg<devgrp_diepctl10::DevgrpDiepctl10Spec>;
#[doc = "Endpoint_number: 10"]
pub mod devgrp_diepctl10;
#[doc = "devgrp_diepint10 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint10::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint10`]
module"]
#[doc(alias = "devgrp_diepint10")]
pub type DevgrpDiepint10 = crate::Reg<devgrp_diepint10::DevgrpDiepint10Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint10;
#[doc = "devgrp_dieptsiz10 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz10`]
module"]
#[doc(alias = "devgrp_dieptsiz10")]
pub type DevgrpDieptsiz10 = crate::Reg<devgrp_dieptsiz10::DevgrpDieptsiz10Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz10;
#[doc = "devgrp_diepdma10 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma10::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma10`]
module"]
#[doc(alias = "devgrp_diepdma10")]
pub type DevgrpDiepdma10 = crate::Reg<devgrp_diepdma10::DevgrpDiepdma10Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma10;
#[doc = "devgrp_dtxfsts10 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts10::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts10`]
module"]
#[doc(alias = "devgrp_dtxfsts10")]
pub type DevgrpDtxfsts10 = crate::Reg<devgrp_dtxfsts10::DevgrpDtxfsts10Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts10;
#[doc = "devgrp_diepdmab10 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab10::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab10`]
module"]
#[doc(alias = "devgrp_diepdmab10")]
pub type DevgrpDiepdmab10 = crate::Reg<devgrp_diepdmab10::DevgrpDiepdmab10Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab10;
#[doc = "devgrp_diepctl11 (rw) register accessor: Endpoint_number: 11\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl11`]
module"]
#[doc(alias = "devgrp_diepctl11")]
pub type DevgrpDiepctl11 = crate::Reg<devgrp_diepctl11::DevgrpDiepctl11Spec>;
#[doc = "Endpoint_number: 11"]
pub mod devgrp_diepctl11;
#[doc = "devgrp_diepint11 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint11::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint11`]
module"]
#[doc(alias = "devgrp_diepint11")]
pub type DevgrpDiepint11 = crate::Reg<devgrp_diepint11::DevgrpDiepint11Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint11;
#[doc = "devgrp_dieptsiz11 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz11`]
module"]
#[doc(alias = "devgrp_dieptsiz11")]
pub type DevgrpDieptsiz11 = crate::Reg<devgrp_dieptsiz11::DevgrpDieptsiz11Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz11;
#[doc = "devgrp_diepdma11 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma11::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma11`]
module"]
#[doc(alias = "devgrp_diepdma11")]
pub type DevgrpDiepdma11 = crate::Reg<devgrp_diepdma11::DevgrpDiepdma11Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma11;
#[doc = "devgrp_dtxfsts11 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts11::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts11`]
module"]
#[doc(alias = "devgrp_dtxfsts11")]
pub type DevgrpDtxfsts11 = crate::Reg<devgrp_dtxfsts11::DevgrpDtxfsts11Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts11;
#[doc = "devgrp_diepdmab11 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab11::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab11`]
module"]
#[doc(alias = "devgrp_diepdmab11")]
pub type DevgrpDiepdmab11 = crate::Reg<devgrp_diepdmab11::DevgrpDiepdmab11Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab11;
#[doc = "devgrp_diepctl12 (rw) register accessor: Endpoint_number: 12\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl12`]
module"]
#[doc(alias = "devgrp_diepctl12")]
pub type DevgrpDiepctl12 = crate::Reg<devgrp_diepctl12::DevgrpDiepctl12Spec>;
#[doc = "Endpoint_number: 12"]
pub mod devgrp_diepctl12;
#[doc = "devgrp_diepint12 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint12::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint12`]
module"]
#[doc(alias = "devgrp_diepint12")]
pub type DevgrpDiepint12 = crate::Reg<devgrp_diepint12::DevgrpDiepint12Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint12;
#[doc = "devgrp_dieptsiz12 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz12`]
module"]
#[doc(alias = "devgrp_dieptsiz12")]
pub type DevgrpDieptsiz12 = crate::Reg<devgrp_dieptsiz12::DevgrpDieptsiz12Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz12;
#[doc = "devgrp_diepdma12 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma12::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma12`]
module"]
#[doc(alias = "devgrp_diepdma12")]
pub type DevgrpDiepdma12 = crate::Reg<devgrp_diepdma12::DevgrpDiepdma12Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma12;
#[doc = "devgrp_dtxfsts12 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts12::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts12`]
module"]
#[doc(alias = "devgrp_dtxfsts12")]
pub type DevgrpDtxfsts12 = crate::Reg<devgrp_dtxfsts12::DevgrpDtxfsts12Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts12;
#[doc = "devgrp_diepdmab12 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab12::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab12`]
module"]
#[doc(alias = "devgrp_diepdmab12")]
pub type DevgrpDiepdmab12 = crate::Reg<devgrp_diepdmab12::DevgrpDiepdmab12Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab12;
#[doc = "devgrp_diepctl13 (rw) register accessor: Endpoint_number: 13\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl13`]
module"]
#[doc(alias = "devgrp_diepctl13")]
pub type DevgrpDiepctl13 = crate::Reg<devgrp_diepctl13::DevgrpDiepctl13Spec>;
#[doc = "Endpoint_number: 13"]
pub mod devgrp_diepctl13;
#[doc = "devgrp_diepint13 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint13::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint13`]
module"]
#[doc(alias = "devgrp_diepint13")]
pub type DevgrpDiepint13 = crate::Reg<devgrp_diepint13::DevgrpDiepint13Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint13;
#[doc = "devgrp_dieptsiz13 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz13`]
module"]
#[doc(alias = "devgrp_dieptsiz13")]
pub type DevgrpDieptsiz13 = crate::Reg<devgrp_dieptsiz13::DevgrpDieptsiz13Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz13;
#[doc = "devgrp_diepdma13 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma13::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma13`]
module"]
#[doc(alias = "devgrp_diepdma13")]
pub type DevgrpDiepdma13 = crate::Reg<devgrp_diepdma13::DevgrpDiepdma13Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma13;
#[doc = "devgrp_dtxfsts13 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts13::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts13`]
module"]
#[doc(alias = "devgrp_dtxfsts13")]
pub type DevgrpDtxfsts13 = crate::Reg<devgrp_dtxfsts13::DevgrpDtxfsts13Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts13;
#[doc = "devgrp_diepdmab13 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab13::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab13`]
module"]
#[doc(alias = "devgrp_diepdmab13")]
pub type DevgrpDiepdmab13 = crate::Reg<devgrp_diepdmab13::DevgrpDiepdmab13Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab13;
#[doc = "devgrp_diepctl14 (rw) register accessor: Endpoint_number: 14\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl14`]
module"]
#[doc(alias = "devgrp_diepctl14")]
pub type DevgrpDiepctl14 = crate::Reg<devgrp_diepctl14::DevgrpDiepctl14Spec>;
#[doc = "Endpoint_number: 14"]
pub mod devgrp_diepctl14;
#[doc = "devgrp_diepint14 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint14::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint14`]
module"]
#[doc(alias = "devgrp_diepint14")]
pub type DevgrpDiepint14 = crate::Reg<devgrp_diepint14::DevgrpDiepint14Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint14;
#[doc = "devgrp_dieptsiz14 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz14`]
module"]
#[doc(alias = "devgrp_dieptsiz14")]
pub type DevgrpDieptsiz14 = crate::Reg<devgrp_dieptsiz14::DevgrpDieptsiz14Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz14;
#[doc = "devgrp_diepdma14 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma14::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma14`]
module"]
#[doc(alias = "devgrp_diepdma14")]
pub type DevgrpDiepdma14 = crate::Reg<devgrp_diepdma14::DevgrpDiepdma14Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma14;
#[doc = "devgrp_dtxfsts14 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts14::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts14`]
module"]
#[doc(alias = "devgrp_dtxfsts14")]
pub type DevgrpDtxfsts14 = crate::Reg<devgrp_dtxfsts14::DevgrpDtxfsts14Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts14;
#[doc = "devgrp_diepdmab14 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab14::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab14`]
module"]
#[doc(alias = "devgrp_diepdmab14")]
pub type DevgrpDiepdmab14 = crate::Reg<devgrp_diepdmab14::DevgrpDiepdmab14Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab14;
#[doc = "devgrp_diepctl15 (rw) register accessor: Endpoint_number: 15\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepctl15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepctl15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepctl15`]
module"]
#[doc(alias = "devgrp_diepctl15")]
pub type DevgrpDiepctl15 = crate::Reg<devgrp_diepctl15::DevgrpDiepctl15Spec>;
#[doc = "Endpoint_number: 15"]
pub mod devgrp_diepctl15;
#[doc = "devgrp_diepint15 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepint15::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepint15`]
module"]
#[doc(alias = "devgrp_diepint15")]
pub type DevgrpDiepint15 = crate::Reg<devgrp_diepint15::DevgrpDiepint15Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_diepint15;
#[doc = "devgrp_dieptsiz15 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dieptsiz15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_dieptsiz15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dieptsiz15`]
module"]
#[doc(alias = "devgrp_dieptsiz15")]
pub type DevgrpDieptsiz15 = crate::Reg<devgrp_dieptsiz15::DevgrpDieptsiz15Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_dieptsiz15;
#[doc = "devgrp_diepdma15 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdma15::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_diepdma15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdma15`]
module"]
#[doc(alias = "devgrp_diepdma15")]
pub type DevgrpDiepdma15 = crate::Reg<devgrp_diepdma15::DevgrpDiepdma15Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_diepdma15;
#[doc = "devgrp_dtxfsts15 (r) register accessor: This register contains the free space information for the Device IN endpoint TxFIFO.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_dtxfsts15::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_dtxfsts15`]
module"]
#[doc(alias = "devgrp_dtxfsts15")]
pub type DevgrpDtxfsts15 = crate::Reg<devgrp_dtxfsts15::DevgrpDtxfsts15Spec>;
#[doc = "This register contains the free space information for the Device IN endpoint TxFIFO."]
pub mod devgrp_dtxfsts15;
#[doc = "devgrp_diepdmab15 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_diepdmab15::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_diepdmab15`]
module"]
#[doc(alias = "devgrp_diepdmab15")]
pub type DevgrpDiepdmab15 = crate::Reg<devgrp_diepdmab15::DevgrpDiepdmab15Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_diepdmab15;
#[doc = "devgrp_doepctl0 (rw) register accessor: This is Control OUT Endpoint 0 Control register.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl0`]
module"]
#[doc(alias = "devgrp_doepctl0")]
pub type DevgrpDoepctl0 = crate::Reg<devgrp_doepctl0::DevgrpDoepctl0Spec>;
#[doc = "This is Control OUT Endpoint 0 Control register."]
pub mod devgrp_doepctl0;
#[doc = "devgrp_doepint0 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint0`]
module"]
#[doc(alias = "devgrp_doepint0")]
pub type DevgrpDoepint0 = crate::Reg<devgrp_doepint0::DevgrpDoepint0Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint0;
#[doc = "devgrp_doeptsiz0 (rw) register accessor: The application must modify this register before enabling endpoint 0. Once endpoint 0 is enabled using Endpoint Enable bit of the Device Control Endpoint 0 Control registers (DIEPCTL0.EPEna/DOEPCTL0.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit. Nonzero endpoints use the registers for endpoints 1 to 15. When Scatter/Gather DMA mode is enabled, this register must not be programmed by the application. If the application reads this register when Scatter/Gather DMA mode is enabled, the core returns all zeros.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz0::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz0`]
module"]
#[doc(alias = "devgrp_doeptsiz0")]
pub type DevgrpDoeptsiz0 = crate::Reg<devgrp_doeptsiz0::DevgrpDoeptsiz0Spec>;
#[doc = "The application must modify this register before enabling endpoint 0. Once endpoint 0 is enabled using Endpoint Enable bit of the Device Control Endpoint 0 Control registers (DIEPCTL0.EPEna/DOEPCTL0.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit. Nonzero endpoints use the registers for endpoints 1 to 15. When Scatter/Gather DMA mode is enabled, this register must not be programmed by the application. If the application reads this register when Scatter/Gather DMA mode is enabled, the core returns all zeros."]
pub mod devgrp_doeptsiz0;
#[doc = "devgrp_doepdma0 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma0::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma0::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma0`]
module"]
#[doc(alias = "devgrp_doepdma0")]
pub type DevgrpDoepdma0 = crate::Reg<devgrp_doepdma0::DevgrpDoepdma0Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_doepdma0;
#[doc = "devgrp_doepdmab0 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab0::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab0`]
module"]
#[doc(alias = "devgrp_doepdmab0")]
pub type DevgrpDoepdmab0 = crate::Reg<devgrp_doepdmab0::DevgrpDoepdmab0Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab0;
#[doc = "devgrp_doepctl1 (rw) register accessor: Out Endpoint 1.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl1`]
module"]
#[doc(alias = "devgrp_doepctl1")]
pub type DevgrpDoepctl1 = crate::Reg<devgrp_doepctl1::DevgrpDoepctl1Spec>;
#[doc = "Out Endpoint 1."]
pub mod devgrp_doepctl1;
#[doc = "devgrp_doepint1 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint1`]
module"]
#[doc(alias = "devgrp_doepint1")]
pub type DevgrpDoepint1 = crate::Reg<devgrp_doepint1::DevgrpDoepint1Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint1;
#[doc = "devgrp_doeptsiz1 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz1::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz1`]
module"]
#[doc(alias = "devgrp_doeptsiz1")]
pub type DevgrpDoeptsiz1 = crate::Reg<devgrp_doeptsiz1::DevgrpDoeptsiz1Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz1;
#[doc = "devgrp_doepdma1 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma1::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma1::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma1`]
module"]
#[doc(alias = "devgrp_doepdma1")]
pub type DevgrpDoepdma1 = crate::Reg<devgrp_doepdma1::DevgrpDoepdma1Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_doepdma1;
#[doc = "devgrp_doepdmab1 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab1::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab1`]
module"]
#[doc(alias = "devgrp_doepdmab1")]
pub type DevgrpDoepdmab1 = crate::Reg<devgrp_doepdmab1::DevgrpDoepdmab1Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab1;
#[doc = "devgrp_DOEPCTL2 (rw) register accessor: Out Endpoint 2.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl2`]
module"]
#[doc(alias = "devgrp_DOEPCTL2")]
pub type DevgrpDoepctl2 = crate::Reg<devgrp_doepctl2::DevgrpDoepctl2Spec>;
#[doc = "Out Endpoint 2."]
pub mod devgrp_doepctl2;
#[doc = "devgrp_doepint2 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint2`]
module"]
#[doc(alias = "devgrp_doepint2")]
pub type DevgrpDoepint2 = crate::Reg<devgrp_doepint2::DevgrpDoepint2Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint2;
#[doc = "devgrp_doeptsiz2 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz2::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz2`]
module"]
#[doc(alias = "devgrp_doeptsiz2")]
pub type DevgrpDoeptsiz2 = crate::Reg<devgrp_doeptsiz2::DevgrpDoeptsiz2Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz2;
#[doc = "devgrp_doepdma2 (rw) register accessor: DMA Addressing.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma2::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma2::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma2`]
module"]
#[doc(alias = "devgrp_doepdma2")]
pub type DevgrpDoepdma2 = crate::Reg<devgrp_doepdma2::DevgrpDoepdma2Spec>;
#[doc = "DMA Addressing."]
pub mod devgrp_doepdma2;
#[doc = "devgrp_doepdmab2 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab2::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab2`]
module"]
#[doc(alias = "devgrp_doepdmab2")]
pub type DevgrpDoepdmab2 = crate::Reg<devgrp_doepdmab2::DevgrpDoepdmab2Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab2;
#[doc = "devgrp_DOEPCTL3 (rw) register accessor: Out Endpoint 3.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl3`]
module"]
#[doc(alias = "devgrp_DOEPCTL3")]
pub type DevgrpDoepctl3 = crate::Reg<devgrp_doepctl3::DevgrpDoepctl3Spec>;
#[doc = "Out Endpoint 3."]
pub mod devgrp_doepctl3;
#[doc = "devgrp_doepint3 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint3`]
module"]
#[doc(alias = "devgrp_doepint3")]
pub type DevgrpDoepint3 = crate::Reg<devgrp_doepint3::DevgrpDoepint3Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint3;
#[doc = "devgrp_doeptsiz3 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz3::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz3`]
module"]
#[doc(alias = "devgrp_doeptsiz3")]
pub type DevgrpDoeptsiz3 = crate::Reg<devgrp_doeptsiz3::DevgrpDoeptsiz3Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz3;
#[doc = "devgrp_doepdma3 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma3::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma3::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma3`]
module"]
#[doc(alias = "devgrp_doepdma3")]
pub type DevgrpDoepdma3 = crate::Reg<devgrp_doepdma3::DevgrpDoepdma3Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma3;
#[doc = "devgrp_doepdmab3 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab3::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab3`]
module"]
#[doc(alias = "devgrp_doepdmab3")]
pub type DevgrpDoepdmab3 = crate::Reg<devgrp_doepdmab3::DevgrpDoepdmab3Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab3;
#[doc = "devgrp_doepctl4 (rw) register accessor: Out Endpoint 4.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl4`]
module"]
#[doc(alias = "devgrp_doepctl4")]
pub type DevgrpDoepctl4 = crate::Reg<devgrp_doepctl4::DevgrpDoepctl4Spec>;
#[doc = "Out Endpoint 4."]
pub mod devgrp_doepctl4;
#[doc = "devgrp_Doepint4 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint4`]
module"]
#[doc(alias = "devgrp_Doepint4")]
pub type DevgrpDoepint4 = crate::Reg<devgrp_doepint4::DevgrpDoepint4Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint4;
#[doc = "devgrp_doeptsiz4 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz4::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz4`]
module"]
#[doc(alias = "devgrp_doeptsiz4")]
pub type DevgrpDoeptsiz4 = crate::Reg<devgrp_doeptsiz4::DevgrpDoeptsiz4Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz4;
#[doc = "devgrp_doepdma4 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma4::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma4::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma4`]
module"]
#[doc(alias = "devgrp_doepdma4")]
pub type DevgrpDoepdma4 = crate::Reg<devgrp_doepdma4::DevgrpDoepdma4Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma4;
#[doc = "devgrp_doepdmab4 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab4::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab4`]
module"]
#[doc(alias = "devgrp_doepdmab4")]
pub type DevgrpDoepdmab4 = crate::Reg<devgrp_doepdmab4::DevgrpDoepdmab4Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab4;
#[doc = "devgrp_doepctl5 (rw) register accessor: Out Endpoint 5.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl5`]
module"]
#[doc(alias = "devgrp_doepctl5")]
pub type DevgrpDoepctl5 = crate::Reg<devgrp_doepctl5::DevgrpDoepctl5Spec>;
#[doc = "Out Endpoint 5."]
pub mod devgrp_doepctl5;
#[doc = "devgrp_doepint5 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint5::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint5`]
module"]
#[doc(alias = "devgrp_doepint5")]
pub type DevgrpDoepint5 = crate::Reg<devgrp_doepint5::DevgrpDoepint5Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint5;
#[doc = "devgrp_doeptsiz5 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz5::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz5`]
module"]
#[doc(alias = "devgrp_doeptsiz5")]
pub type DevgrpDoeptsiz5 = crate::Reg<devgrp_doeptsiz5::DevgrpDoeptsiz5Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz5;
#[doc = "devgrp_doepdma5 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma5::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma5::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma5`]
module"]
#[doc(alias = "devgrp_doepdma5")]
pub type DevgrpDoepdma5 = crate::Reg<devgrp_doepdma5::DevgrpDoepdma5Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma5;
#[doc = "devgrp_doepdmab5 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab5::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab5`]
module"]
#[doc(alias = "devgrp_doepdmab5")]
pub type DevgrpDoepdmab5 = crate::Reg<devgrp_doepdmab5::DevgrpDoepdmab5Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab5;
#[doc = "devgrp_doepctl6 (rw) register accessor: Out Endpoint 6.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl6`]
module"]
#[doc(alias = "devgrp_doepctl6")]
pub type DevgrpDoepctl6 = crate::Reg<devgrp_doepctl6::DevgrpDoepctl6Spec>;
#[doc = "Out Endpoint 6."]
pub mod devgrp_doepctl6;
#[doc = "devgrp_doepint6 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint6::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint6`]
module"]
#[doc(alias = "devgrp_doepint6")]
pub type DevgrpDoepint6 = crate::Reg<devgrp_doepint6::DevgrpDoepint6Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint6;
#[doc = "devgrp_doeptsiz6 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz6::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz6`]
module"]
#[doc(alias = "devgrp_doeptsiz6")]
pub type DevgrpDoeptsiz6 = crate::Reg<devgrp_doeptsiz6::DevgrpDoeptsiz6Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz6;
#[doc = "devgrp_doepdma6 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma6::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma6::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma6`]
module"]
#[doc(alias = "devgrp_doepdma6")]
pub type DevgrpDoepdma6 = crate::Reg<devgrp_doepdma6::DevgrpDoepdma6Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma6;
#[doc = "devgrp_doepdmab6 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab6::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab6`]
module"]
#[doc(alias = "devgrp_doepdmab6")]
pub type DevgrpDoepdmab6 = crate::Reg<devgrp_doepdmab6::DevgrpDoepdmab6Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab6;
#[doc = "devgrp_doepctl7 (rw) register accessor: Endpoint_number: 7\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl7`]
module"]
#[doc(alias = "devgrp_doepctl7")]
pub type DevgrpDoepctl7 = crate::Reg<devgrp_doepctl7::DevgrpDoepctl7Spec>;
#[doc = "Endpoint_number: 7"]
pub mod devgrp_doepctl7;
#[doc = "devgrp_doepint7 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint7::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint7`]
module"]
#[doc(alias = "devgrp_doepint7")]
pub type DevgrpDoepint7 = crate::Reg<devgrp_doepint7::DevgrpDoepint7Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint7;
#[doc = "devgrp_doeptsiz7 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz7::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz7`]
module"]
#[doc(alias = "devgrp_doeptsiz7")]
pub type DevgrpDoeptsiz7 = crate::Reg<devgrp_doeptsiz7::DevgrpDoeptsiz7Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz7;
#[doc = "devgrp_doepdma7 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma7::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma7::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma7`]
module"]
#[doc(alias = "devgrp_doepdma7")]
pub type DevgrpDoepdma7 = crate::Reg<devgrp_doepdma7::DevgrpDoepdma7Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma7;
#[doc = "devgrp_doepdmab7 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab7::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab7`]
module"]
#[doc(alias = "devgrp_doepdmab7")]
pub type DevgrpDoepdmab7 = crate::Reg<devgrp_doepdmab7::DevgrpDoepdmab7Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab7;
#[doc = "devgrp_doepctl8 (rw) register accessor: Out Endpoint 8.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl8`]
module"]
#[doc(alias = "devgrp_doepctl8")]
pub type DevgrpDoepctl8 = crate::Reg<devgrp_doepctl8::DevgrpDoepctl8Spec>;
#[doc = "Out Endpoint 8."]
pub mod devgrp_doepctl8;
#[doc = "devgrp_doepint8 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint8::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint8`]
module"]
#[doc(alias = "devgrp_doepint8")]
pub type DevgrpDoepint8 = crate::Reg<devgrp_doepint8::DevgrpDoepint8Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint8;
#[doc = "devgrp_doeptsiz8 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz8::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz8`]
module"]
#[doc(alias = "devgrp_doeptsiz8")]
pub type DevgrpDoeptsiz8 = crate::Reg<devgrp_doeptsiz8::DevgrpDoeptsiz8Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz8;
#[doc = "devgrp_doepdma8 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma8::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma8::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma8`]
module"]
#[doc(alias = "devgrp_doepdma8")]
pub type DevgrpDoepdma8 = crate::Reg<devgrp_doepdma8::DevgrpDoepdma8Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma8;
#[doc = "devgrp_doepdmab8 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab8::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab8`]
module"]
#[doc(alias = "devgrp_doepdmab8")]
pub type DevgrpDoepdmab8 = crate::Reg<devgrp_doepdmab8::DevgrpDoepdmab8Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab8;
#[doc = "devgrp_doepctl9 (rw) register accessor: Out Endpoint 9.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl9`]
module"]
#[doc(alias = "devgrp_doepctl9")]
pub type DevgrpDoepctl9 = crate::Reg<devgrp_doepctl9::DevgrpDoepctl9Spec>;
#[doc = "Out Endpoint 9."]
pub mod devgrp_doepctl9;
#[doc = "devgrp_doepint9 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint9::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint9`]
module"]
#[doc(alias = "devgrp_doepint9")]
pub type DevgrpDoepint9 = crate::Reg<devgrp_doepint9::DevgrpDoepint9Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint9;
#[doc = "devgrp_doeptsiz9 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz9::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz9`]
module"]
#[doc(alias = "devgrp_doeptsiz9")]
pub type DevgrpDoeptsiz9 = crate::Reg<devgrp_doeptsiz9::DevgrpDoeptsiz9Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz9;
#[doc = "devgrp_doepdma9 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma9::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma9::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma9`]
module"]
#[doc(alias = "devgrp_doepdma9")]
pub type DevgrpDoepdma9 = crate::Reg<devgrp_doepdma9::DevgrpDoepdma9Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma9;
#[doc = "devgrp_doepdmab9 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab9::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab9`]
module"]
#[doc(alias = "devgrp_doepdmab9")]
pub type DevgrpDoepdmab9 = crate::Reg<devgrp_doepdmab9::DevgrpDoepdmab9Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab9;
#[doc = "devgrp_doepctl10 (rw) register accessor: Out Endpoint 10.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl10`]
module"]
#[doc(alias = "devgrp_doepctl10")]
pub type DevgrpDoepctl10 = crate::Reg<devgrp_doepctl10::DevgrpDoepctl10Spec>;
#[doc = "Out Endpoint 10."]
pub mod devgrp_doepctl10;
#[doc = "devgrp_doepint10 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint10::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint10`]
module"]
#[doc(alias = "devgrp_doepint10")]
pub type DevgrpDoepint10 = crate::Reg<devgrp_doepint10::DevgrpDoepint10Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint10;
#[doc = "devgrp_doeptsiz10 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz10::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz10`]
module"]
#[doc(alias = "devgrp_doeptsiz10")]
pub type DevgrpDoeptsiz10 = crate::Reg<devgrp_doeptsiz10::DevgrpDoeptsiz10Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz10;
#[doc = "devgrp_doepdma10 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma10::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma10::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma10`]
module"]
#[doc(alias = "devgrp_doepdma10")]
pub type DevgrpDoepdma10 = crate::Reg<devgrp_doepdma10::DevgrpDoepdma10Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma10;
#[doc = "devgrp_doepdmab10 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab10::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab10`]
module"]
#[doc(alias = "devgrp_doepdmab10")]
pub type DevgrpDoepdmab10 = crate::Reg<devgrp_doepdmab10::DevgrpDoepdmab10Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab10;
#[doc = "devgrp_doepctl11 (rw) register accessor: Out Endpoint 11.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl11`]
module"]
#[doc(alias = "devgrp_doepctl11")]
pub type DevgrpDoepctl11 = crate::Reg<devgrp_doepctl11::DevgrpDoepctl11Spec>;
#[doc = "Out Endpoint 11."]
pub mod devgrp_doepctl11;
#[doc = "devgrp_doepint11 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint11::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint11`]
module"]
#[doc(alias = "devgrp_doepint11")]
pub type DevgrpDoepint11 = crate::Reg<devgrp_doepint11::DevgrpDoepint11Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint11;
#[doc = "devgrp_doeptsiz11 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz11::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz11`]
module"]
#[doc(alias = "devgrp_doeptsiz11")]
pub type DevgrpDoeptsiz11 = crate::Reg<devgrp_doeptsiz11::DevgrpDoeptsiz11Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz11;
#[doc = "devgrp_doepdma11 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma11::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma11::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma11`]
module"]
#[doc(alias = "devgrp_doepdma11")]
pub type DevgrpDoepdma11 = crate::Reg<devgrp_doepdma11::DevgrpDoepdma11Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma11;
#[doc = "devgrp_doepdmab11 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab11::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab11`]
module"]
#[doc(alias = "devgrp_doepdmab11")]
pub type DevgrpDoepdmab11 = crate::Reg<devgrp_doepdmab11::DevgrpDoepdmab11Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab11;
#[doc = "devgrp_doepctl12 (rw) register accessor: Out Endpoint 12.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl12`]
module"]
#[doc(alias = "devgrp_doepctl12")]
pub type DevgrpDoepctl12 = crate::Reg<devgrp_doepctl12::DevgrpDoepctl12Spec>;
#[doc = "Out Endpoint 12."]
pub mod devgrp_doepctl12;
#[doc = "devgrp_doepint12 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint12::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint12`]
module"]
#[doc(alias = "devgrp_doepint12")]
pub type DevgrpDoepint12 = crate::Reg<devgrp_doepint12::DevgrpDoepint12Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint12;
#[doc = "devgrp_doeptsiz12 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz12::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz12`]
module"]
#[doc(alias = "devgrp_doeptsiz12")]
pub type DevgrpDoeptsiz12 = crate::Reg<devgrp_doeptsiz12::DevgrpDoeptsiz12Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz12;
#[doc = "devgrp_doepdma12 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma12::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma12::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma12`]
module"]
#[doc(alias = "devgrp_doepdma12")]
pub type DevgrpDoepdma12 = crate::Reg<devgrp_doepdma12::DevgrpDoepdma12Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma12;
#[doc = "devgrp_doepdmab12 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab12::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab12`]
module"]
#[doc(alias = "devgrp_doepdmab12")]
pub type DevgrpDoepdmab12 = crate::Reg<devgrp_doepdmab12::DevgrpDoepdmab12Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab12;
#[doc = "devgrp_doepctl13 (rw) register accessor: Out Endpoint 13.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl13`]
module"]
#[doc(alias = "devgrp_doepctl13")]
pub type DevgrpDoepctl13 = crate::Reg<devgrp_doepctl13::DevgrpDoepctl13Spec>;
#[doc = "Out Endpoint 13."]
pub mod devgrp_doepctl13;
#[doc = "devgrp_doepint13 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint13::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint13`]
module"]
#[doc(alias = "devgrp_doepint13")]
pub type DevgrpDoepint13 = crate::Reg<devgrp_doepint13::DevgrpDoepint13Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint13;
#[doc = "devgrp_doeptsiz13 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz13::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz13`]
module"]
#[doc(alias = "devgrp_doeptsiz13")]
pub type DevgrpDoeptsiz13 = crate::Reg<devgrp_doeptsiz13::DevgrpDoeptsiz13Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz13;
#[doc = "devgrp_doepdma13 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma13::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma13::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma13`]
module"]
#[doc(alias = "devgrp_doepdma13")]
pub type DevgrpDoepdma13 = crate::Reg<devgrp_doepdma13::DevgrpDoepdma13Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma13;
#[doc = "devgrp_doepdmab13 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab13::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab13`]
module"]
#[doc(alias = "devgrp_doepdmab13")]
pub type DevgrpDoepdmab13 = crate::Reg<devgrp_doepdmab13::DevgrpDoepdmab13Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab13;
#[doc = "devgrp_doepctl14 (rw) register accessor: Out Endpoint 14.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl14`]
module"]
#[doc(alias = "devgrp_doepctl14")]
pub type DevgrpDoepctl14 = crate::Reg<devgrp_doepctl14::DevgrpDoepctl14Spec>;
#[doc = "Out Endpoint 14."]
pub mod devgrp_doepctl14;
#[doc = "devgrp_doepint14 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint14::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint14`]
module"]
#[doc(alias = "devgrp_doepint14")]
pub type DevgrpDoepint14 = crate::Reg<devgrp_doepint14::DevgrpDoepint14Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint14;
#[doc = "devgrp_doeptsiz14 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz14::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz14`]
module"]
#[doc(alias = "devgrp_doeptsiz14")]
pub type DevgrpDoeptsiz14 = crate::Reg<devgrp_doeptsiz14::DevgrpDoeptsiz14Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz14;
#[doc = "devgrp_doepdma14 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma14::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma14::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma14`]
module"]
#[doc(alias = "devgrp_doepdma14")]
pub type DevgrpDoepdma14 = crate::Reg<devgrp_doepdma14::DevgrpDoepdma14Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma14;
#[doc = "devgrp_doepdmab14 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab14::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab14`]
module"]
#[doc(alias = "devgrp_doepdmab14")]
pub type DevgrpDoepdmab14 = crate::Reg<devgrp_doepdmab14::DevgrpDoepdmab14Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab14;
#[doc = "devgrp_doepctl15 (rw) register accessor: Out Endpoint 15.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepctl15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepctl15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepctl15`]
module"]
#[doc(alias = "devgrp_doepctl15")]
pub type DevgrpDoepctl15 = crate::Reg<devgrp_doepctl15::DevgrpDoepctl15Spec>;
#[doc = "Out Endpoint 15."]
pub mod devgrp_doepctl15;
#[doc = "devgrp_doepint15 (r) register accessor: This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepint15::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepint15`]
module"]
#[doc(alias = "devgrp_doepint15")]
pub type DevgrpDoepint15 = crate::Reg<devgrp_doepint15::DevgrpDoepint15Spec>;
#[doc = "This register indicates the status of an endpoint with respect to USB- and AHB-related events. The application must read this register when the OUT Endpoints Interrupt bit or IN Endpoints Interrupt bit of the Core Interrupt register (GINTSTS.OEPInt or GINTSTS.IEPInt, respectively) is set. Before the application can read this register, it must first read the Device All Endpoints Interrupt (DAINT) register to get the exact endpoint number for the Device Endpoint-n Interrupt register. The application must clear the appropriate bit in this register to clear the corresponding bits in the DAINT and GINTSTS registers."]
pub mod devgrp_doepint15;
#[doc = "devgrp_doeptsiz15 (rw) register accessor: The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doeptsiz15::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doeptsiz15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doeptsiz15`]
module"]
#[doc(alias = "devgrp_doeptsiz15")]
pub type DevgrpDoeptsiz15 = crate::Reg<devgrp_doeptsiz15::DevgrpDoeptsiz15Spec>;
#[doc = "The application must modify this register before enabling the endpoint. Once the endpoint is enabled using Endpoint Enable bit of the Device Endpoint-n Control registers (DIEPCTLn.EPEna/DOEPCTLn.EPEna), the core modifies this register. The application can only read this register once the core has cleared the Endpoint Enable bit."]
pub mod devgrp_doeptsiz15;
#[doc = "devgrp_doepdma15 (rw) register accessor: DMA OUT Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdma15::R`].  You can [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`devgrp_doepdma15::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdma15`]
module"]
#[doc(alias = "devgrp_doepdma15")]
pub type DevgrpDoepdma15 = crate::Reg<devgrp_doepdma15::DevgrpDoepdma15Spec>;
#[doc = "DMA OUT Address."]
pub mod devgrp_doepdma15;
#[doc = "devgrp_doepdmab15 (r) register accessor: DMA Buffer Address.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`devgrp_doepdmab15::R`].  See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@devgrp_doepdmab15`]
module"]
#[doc(alias = "devgrp_doepdmab15")]
pub type DevgrpDoepdmab15 = crate::Reg<devgrp_doepdmab15::DevgrpDoepdmab15Spec>;
#[doc = "DMA Buffer Address."]
pub mod devgrp_doepdmab15;
#[doc = "pwrclkgrp_pcgcctl (rw) register accessor: This register is available in Host and Device modes. The application can use this register to control the core's power-down and clock gating features. Because the CSR module is turned off during power-down, this register is implemented in the AHB Slave BIU module.\n\nYou can [`read`](crate::generic::Reg::read) this register and get [`pwrclkgrp_pcgcctl::R`].  You can [`reset`](crate::generic::Reg::reset), [`write`](crate::generic::Reg::write), [`write_with_zero`](crate::generic::Reg::write_with_zero) this register using [`pwrclkgrp_pcgcctl::W`]. You can also [`modify`](crate::generic::Reg::modify) this register. See [API](https://docs.rs/svd2rust/#read--modify--write-api).\n\nFor information about available fields see [`mod@pwrclkgrp_pcgcctl`]
module"]
#[doc(alias = "pwrclkgrp_pcgcctl")]
pub type PwrclkgrpPcgcctl = crate::Reg<pwrclkgrp_pcgcctl::PwrclkgrpPcgcctlSpec>;
#[doc = "This register is available in Host and Device modes. The application can use this register to control the core's power-down and clock gating features. Because the CSR module is turned off during power-down, this register is implemented in the AHB Slave BIU module."]
pub mod pwrclkgrp_pcgcctl;
