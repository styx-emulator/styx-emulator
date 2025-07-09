// SPDX-License-Identifier: BSD-2-Clause
import { AfterViewInit, Component } from "@angular/core";

@Component({
  selector: "app-root",
  templateUrl: "./app.component.html",
  styleUrls: ["./app.component.css"]
})
export class AppComponent implements AfterViewInit {
  title = "Styx Tracing";
  constructor() {
    // This is the effective entry point
    // good place to fetch all data for a cache
  }
  ngAfterViewInit(): void {
    const header = document.getElementById("header");
    const footer = document.getElementById("footer");
    if (header && footer) {
      const headerHeight = header.offsetHeight;
      const footerHeight = footer.offsetHeight;
      document.documentElement.style.setProperty(
        "--header-height",
        `${headerHeight}px`
      );
      document.documentElement.style.setProperty(
        "--footer-height",
        `${footerHeight}px`
      );
    }
  }
}
