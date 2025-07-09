import { Pipe, PipeTransform } from "@angular/core";

@Pipe({
  name: "hex"
})
export class HexPipe implements PipeTransform {
  transform(value: number, exponent = 16): string {
    // return "0x" + value.toString(16);
    return new BaseFmtPipe().transform(value, exponent);
  }
}

@Pipe({
  name: "basefmt"
})
export class BaseFmtPipe implements PipeTransform {
  transform(value: number, exponent = 1): string {
    let prefix = "";
    switch (exponent) {
      case 16:
        prefix = "0x";
        break;
      default:
        prefix = "";
        return "0x" + value.toString(16);
    }
    return prefix + value.toString(exponent);
  }
}
