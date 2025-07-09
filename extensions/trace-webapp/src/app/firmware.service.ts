import { Injectable } from "@angular/core";
import { Target } from "src/generated/args_pb";
import { Architecture as ArchEnum } from "src/generated/emulation_pb";

export const APP_DEFAULT_POWERQUICC_FW = "/firmware/powerquicc-1.bin";
export const APP_DEFAULT_KINETIS21_FW = "/firmware/k21-1.bin";
export const APP_DEFAULT_STM_FW = "/firmware/arm_stm32f107_blink_gpio.bin";
export const APP_DEFAULT_CYCLONEV_FW =
  "/firmware/arm-cortex-a9-16550-usart-app.bin";
export const APP_DEFAULT_BLACKFIN_FW = "/firmware/bfin512.bin";

export class Variants {
  public static get ArmCortexM3(): string {
    return "ArmCortexM3";
  }
  public static get ArmCortexA9(): string {
    return "ArmCortexA9";
  }
  public static get ArmCortexM4(): string {
    return "ArmCortexM4";
  }
  public static get Mpc852T(): string {
    return "Mpc852T";
  }
  public static get Bf512(): string {
    return "Bf512";
  }
}

@Injectable({
  providedIn: "root"
})
export class FirmwareService {
  constructor() {}

  getArchitecture(target: Target): ArchEnum {
    switch (target) {
      case Target.KINETIS21:
        return ArchEnum.ARM;
      case Target.STM32F107:
        return ArchEnum.ARM;
      case Target.POWERQUICC:
        return ArchEnum.PPC32;
      case Target.CYCLONEV:
        return ArchEnum.ARM;
      case Target.BLACKFIN512:
        return ArchEnum.BLACKFIN;
    }
  }

  getVariant(target: Target): string {
    switch (target) {
      case Target.KINETIS21:
        return Variants.ArmCortexM4;

      case Target.STM32F107:
        return Variants.ArmCortexM3;

      case Target.POWERQUICC:
        return Variants.Mpc852T;

      case Target.CYCLONEV:
        return Variants.ArmCortexA9;

      case Target.BLACKFIN512:
        return Variants.Bf512;
    }
  }

  getVariants(architecture: ArchEnum): Array<string> {
    switch (architecture) {
      case ArchEnum.ARM:
        return [Variants.ArmCortexM4, Variants.ArmCortexM3];
      case ArchEnum.PPC32:
        return [Variants.Mpc852T];
      default:
        return [];
    }
  }

  getAvailableFirmwares(variant: string): Array<string> {
    if (variant == Variants.ArmCortexM4) return [APP_DEFAULT_KINETIS21_FW];

    if (variant == Variants.ArmCortexM3) return [APP_DEFAULT_STM_FW];

    if (variant == Variants.Mpc852T) return [APP_DEFAULT_POWERQUICC_FW];

    if (variant == Variants.ArmCortexA9) return [APP_DEFAULT_CYCLONEV_FW];

    if (variant == Variants.Bf512) return [APP_DEFAULT_BLACKFIN_FW];

    return [];
  }
}
