import { NgModule } from "@angular/core";
import { RouterModule, Routes } from "@angular/router";
import { AboutComponent } from "./about/about.component";
import { BlankComponent } from "./blank/blank.component";
import { EditWorkspaceProgramComponent } from "./edit-workspace-program/edit-workspace-program.component";
import { EmuRequestFormComponent } from "./emu-request-form/emu-request-form.component";
import { EmulateComponent } from "./emulate/emulate.component";
import { ListWorkspaceProgramComponent } from "./list-workspace-program/list-workspace-program.component";
import { SessionTableComponent } from "./session-table/session-table.component";
export enum _Rts {
  WspList = "list-ws-programs",
  WspEdit = "ws-program",
  SessionList = "list-sessions",
  NewSession = "new-session",
  Trace = "trace",
  About = "about",
  Blank = "blank"
}
export enum Rts {
  WspList = `/${_Rts.WspList}`,
  WspEdit = `/${_Rts.WspEdit}`,
  SessionList = `/${_Rts.SessionList}`,
  NewSession = `/${_Rts.NewSession}`,
  Trace = `/${_Rts.Trace}`,
  About = `/${_Rts.About}`,
  Blank = `/${_Rts.Blank}`
}
export const DefaultRoute = _Rts.SessionList;

const routes: Routes = [
  { path: "", redirectTo: DefaultRoute, pathMatch: "full" },
  {
    path: `${_Rts.WspEdit}/:op/:id`,
    component: EditWorkspaceProgramComponent
  },

  { path: _Rts.WspList, component: ListWorkspaceProgramComponent },
  { path: _Rts.NewSession, component: EmuRequestFormComponent },
  { path: _Rts.SessionList, component: SessionTableComponent },
  { path: `${_Rts.Trace}/:traceSessionId`, component: EmulateComponent },
  { path: _Rts.Blank, component: BlankComponent },
  { path: _Rts.About, component: AboutComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {}
