import { Component } from "@angular/core";
import { Rts } from "../app-routing.module";

@Component({
  selector: "app-side-nav",
  templateUrl: "./side-nav.component.html",
  styleUrl: "./side-nav.component.css"
})
export class SideNavComponent {
  public Rts = Rts;
}
