// SPDX-License-Identifier: BSD-2-Clause
import { Component } from "@angular/core";
import { Rts } from "../app-routing.module";

@Component({
  selector: "app-app-toolbar",
  templateUrl: "./app-toolbar.component.html",
  styleUrl: "./app-toolbar.component.css"
})
export class AppToolbarComponent {
  public Rts = Rts;
}
