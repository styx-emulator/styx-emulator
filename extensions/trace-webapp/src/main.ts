// SPDX-License-Identifier: BSD-2-Clause
/// <reference types="@angular/localize" />

import { platformBrowserDynamic } from "@angular/platform-browser-dynamic";

import { AppModule } from "./app/app.module";

platformBrowserDynamic()
  .bootstrapModule(AppModule)
  .catch((err) => console.error(err));
