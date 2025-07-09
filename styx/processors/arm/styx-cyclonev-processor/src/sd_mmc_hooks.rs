// SPDX-License-Identifier: BSD-2-Clause
use styx_core::prelude::*;
use tracing::{debug, warn};

use super::sd_mmc::{SDMMC_BASE, SDMMC_STRUCT_SIZE};
use styx_cyclone_v_hps_sys::{generic::RegisterSpec, sdmmc};

// userdata is `Arc<CycloneVSDMMC>`
pub fn sdmmc_region_read_debug_hook(
    _proc: CoreHandle,
    address: u64,
    size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    if address < SDMMC_BASE || address > (SDMMC_BASE + SDMMC_STRUCT_SIZE as u64) {
        warn!("sdmmc_region_read_hook got a read not in the struct @ address {address:#08x}");
        return Ok(());
    }

    // address is in bounds
    let offset = address.saturating_sub(SDMMC_BASE);
    let read_data = u32::from_le_bytes(data[..size as usize].try_into().unwrap());

    if offset == sdmmc::ctrl::CtrlSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::ctrl");
    } else if offset == sdmmc::pwren::PwrenSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::pwren");
    } else if offset == sdmmc::clkdiv::ClkdivSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::clkdiv");
    } else if offset == sdmmc::clksrc::ClksrcSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::clksrc");
    } else if offset == sdmmc::clkena::ClkenaSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::clkena");
    } else if offset == sdmmc::tmout::TmoutSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::tmout");
    } else if offset == sdmmc::ctype::CtypeSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::ctype");
    } else if offset == sdmmc::blksiz::BlksizSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::blksiz");
    } else if offset == sdmmc::bytcnt::BytcntSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::bytcnt");
    } else if offset == sdmmc::intmask::IntmaskSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::intmask");
    } else if offset == sdmmc::cmdarg::CmdargSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::cmdarg");
    } else if offset == sdmmc::cmd::CmdSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::cmd");
    } else if offset == sdmmc::resp0::Resp0Spec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::resp0");
    } else if offset == sdmmc::resp1::Resp1Spec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::resp1");
    } else if offset == sdmmc::resp2::Resp2Spec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::resp2");
    } else if offset == sdmmc::resp3::Resp3Spec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::resp3");
    } else if offset == sdmmc::mintsts::MintstsSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::mintsts");
    } else if offset == sdmmc::rintsts::RintstsSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::rintsts");
    } else if offset == sdmmc::status::StatusSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::status");
    } else if offset == sdmmc::fifoth::FifothSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::fifoth");
    } else if offset == sdmmc::cdetect::CdetectSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::cdetect");
    } else if offset == sdmmc::wrtprt::WrtprtSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::wrtprt");
    } else if offset == sdmmc::tcbcnt::TcbcntSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::tcbcnt");
    } else if offset == sdmmc::tbbcnt::TbbcntSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::tbbcnt");
    } else if offset == sdmmc::debnce::DebnceSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::debnce");
    } else if offset == sdmmc::usrid::UsridSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::debnce");
    } else if offset == sdmmc::verid::VeridSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::verid");
    } else if offset == sdmmc::hcon::HconSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::hcon");
    } else if offset == sdmmc::uhs_reg::UhsRegSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::uhs_reg");
    } else if offset == sdmmc::rst_n::RstNSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::rst_n");
    } else if offset == sdmmc::bmod::BmodSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::bmod");
    } else if offset == sdmmc::pldmnd::PldmndSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::pldmnd");
    } else if offset == sdmmc::dbaddr::DbaddrSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::dbaddr");
    } else if offset == sdmmc::idsts::IdstsSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::idsts");
    } else if offset == sdmmc::idinten::IdintenSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::idinten");
    } else if offset == sdmmc::dscaddr::DscaddrSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::dscaddr");
    } else if offset == sdmmc::bufaddr::BufaddrSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::bufaddr");
    } else if offset == sdmmc::cardthrctl::CardthrctlSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::cardthrctl");
    } else if offset == sdmmc::back_end_power_r::BackEndPowerRSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::back_end_power_r");
    } else if offset == sdmmc::data::DataSpec::OFFSET {
        debug!("Read `{read_data:#08x}` from SDMMC::data");
    } else {
        debug!("Read `{read_data:#08x}` from Bad SDMMC_WRITE_HOOK @ `{address:#08x}`");
    }

    Ok(())
}

// userdata is `Arc<CycloneVSDMMC>`
pub fn sdmmc_region_write_debug_hook(
    _proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    if address < SDMMC_BASE || address > (SDMMC_BASE + SDMMC_STRUCT_SIZE as u64) {
        warn!("sdmmc_region_read_hook got a read not in the struct @ address {address:#08x}");
        return Ok(());
    }

    // address is in bounds
    let offset = address.saturating_sub(SDMMC_BASE);
    let written_data = u32::from_le_bytes(data[..size as usize].try_into().unwrap());

    if offset == sdmmc::ctrl::CtrlSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::ctrl");
    } else if offset == sdmmc::pwren::PwrenSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::pwren");
    } else if offset == sdmmc::clkdiv::ClkdivSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::clkdiv");
    } else if offset == sdmmc::clksrc::ClksrcSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::clksrc");
    } else if offset == sdmmc::clkena::ClkenaSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::clkena");
    } else if offset == sdmmc::tmout::TmoutSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::tmout");
    } else if offset == sdmmc::ctype::CtypeSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::ctype");
    } else if offset == sdmmc::blksiz::BlksizSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::blksiz");
    } else if offset == sdmmc::bytcnt::BytcntSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::bytcnt");
    } else if offset == sdmmc::intmask::IntmaskSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::intmask");
    } else if offset == sdmmc::cmdarg::CmdargSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::cmdarg");
    } else if offset == sdmmc::cmd::CmdSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::cmd");
    } else if offset == sdmmc::resp0::Resp0Spec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::resp0");
    } else if offset == sdmmc::resp1::Resp1Spec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::resp1");
    } else if offset == sdmmc::resp2::Resp2Spec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::resp2");
    } else if offset == sdmmc::resp3::Resp3Spec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::resp3");
    } else if offset == sdmmc::mintsts::MintstsSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::mintsts");
    } else if offset == sdmmc::rintsts::RintstsSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::rintsts");
    } else if offset == sdmmc::status::StatusSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::status");
    } else if offset == sdmmc::fifoth::FifothSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::fifoth");
    } else if offset == sdmmc::cdetect::CdetectSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::cdetect");
    } else if offset == sdmmc::wrtprt::WrtprtSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::wrtprt");
    } else if offset == sdmmc::tcbcnt::TcbcntSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::tcbcnt");
    } else if offset == sdmmc::tbbcnt::TbbcntSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::tbbcnt");
    } else if offset == sdmmc::debnce::DebnceSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::debnce");
    } else if offset == sdmmc::usrid::UsridSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::debnce");
    } else if offset == sdmmc::verid::VeridSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::verid");
    } else if offset == sdmmc::hcon::HconSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::hcon");
    } else if offset == sdmmc::uhs_reg::UhsRegSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::uhs_reg");
    } else if offset == sdmmc::rst_n::RstNSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::rst_n");
    } else if offset == sdmmc::bmod::BmodSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::bmod");
    } else if offset == sdmmc::pldmnd::PldmndSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::pldmnd");
    } else if offset == sdmmc::dbaddr::DbaddrSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::dbaddr");
    } else if offset == sdmmc::idsts::IdstsSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::idsts");
    } else if offset == sdmmc::idinten::IdintenSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::idinten");
    } else if offset == sdmmc::dscaddr::DscaddrSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::dscaddr");
    } else if offset == sdmmc::bufaddr::BufaddrSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::bufaddr");
    } else if offset == sdmmc::cardthrctl::CardthrctlSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::cardthrctl");
    } else if offset == sdmmc::back_end_power_r::BackEndPowerRSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::back_end_power_r");
    } else if offset == sdmmc::data::DataSpec::OFFSET {
        debug!("Wrote `{written_data:#08x}` from SDMMC::data");
    } else {
        debug!("Wrote `{written_data:#08x}` from Bad SDMMC_WRITE_HOOK @ `{address:#08x}`");
    }

    Ok(())
}
