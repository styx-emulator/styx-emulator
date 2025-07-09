// SPDX-License-Identifier: BSD-2-Clause
import { Pipe, PipeTransform } from "@angular/core";

@Pipe({
  name: "trimEnum"
})
export class TrimEnumPipe implements PipeTransform {
  transform(value: string): string {
    return value.split("::").slice(-1)[0];
  }
}
