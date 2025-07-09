import { CdkAccordionModule } from "@angular/cdk/accordion";
import { CdkVirtualScrollViewport } from "@angular/cdk/scrolling";
import { CdkStepperModule } from "@angular/cdk/stepper";
import { CdkTableModule } from "@angular/cdk/table";
import { CdkTreeModule } from "@angular/cdk/tree";
import { NgModule } from "@angular/core";
import { FormsModule, ReactiveFormsModule } from "@angular/forms";
import { MatAutocompleteModule } from "@angular/material/autocomplete";
import { MatBadgeModule } from "@angular/material/badge";
import { MatButtonModule } from "@angular/material/button";
import { MatCardModule } from "@angular/material/card";
import { MatCheckboxModule } from "@angular/material/checkbox";
import { MatChipsModule } from "@angular/material/chips";
import { MatDividerModule } from "@angular/material/divider";
import { MatExpansionModule } from "@angular/material/expansion";
import { MatFormFieldModule } from "@angular/material/form-field";
import { MatGridListModule } from "@angular/material/grid-list";
import { MatIconModule } from "@angular/material/icon";
import { MatInputModule } from "@angular/material/input";
import { MatListModule } from "@angular/material/list";
import { MatPaginatorModule } from "@angular/material/paginator";
import { MatProgressBarModule } from "@angular/material/progress-bar";
import { MatRadioModule } from "@angular/material/radio";
import { MatSelectModule } from "@angular/material/select";
import { MatSidenavModule } from "@angular/material/sidenav";
import { MatSortModule } from "@angular/material/sort";
import { MatTableModule } from "@angular/material/table";
import { MatTabsModule } from "@angular/material/tabs";
import { MatToolbarModule } from "@angular/material/toolbar";
import { MatTooltipModule } from "@angular/material/tooltip";
import { BrowserModule } from "@angular/platform-browser";
import { BrowserAnimationsModule } from "@angular/platform-browser/animations";
import {
  NgbAlertModule,
  NgbModule,
  NgbTypeaheadConfig
} from "@ng-bootstrap/ng-bootstrap";
import { AngularSplitModule } from "angular-split";
import { TrimEnumPipe } from "src/pipes/trim-enum.pipe";
import { AboutComponent } from "./about/about.component";
import { AppRoutingModule } from "./app-routing.module";
import { AppToolbarComponent } from "./app-toolbar/app-toolbar.component";
import { AppComponent } from "./app.component";
import { EditProgramComponent } from "./edit-program/edit-program.component";
import { EditWorkspaceProgramComponent } from "./edit-workspace-program/edit-workspace-program.component";
import { EmuRequestFormComponent } from "./emu-request-form/emu-request-form.component";
import { EmulateComponent } from "./emulate/emulate.component";
import {
  MetaService,
  TraceAppService
} from "./grpc-services/trace-app.service";
import { TyphunixService } from "./grpc-services/typhunix.service";
import { WorkspaceService } from "./grpc-services/workspace.service";
import { HexPipe } from "./hex.pipe";
import { ListWorkspaceProgramComponent } from "./list-workspace-program/list-workspace-program.component";
import { ProgramsComponent } from "./programs/programs.component";
import { SessionTableComponent } from "./session-table/session-table.component";
import { SideNavComponent } from "./side-nav/side-nav.component";
import { TraceConfigsComponent } from "./trace-configs/trace-configs.component";
import { VarTableComponent } from "./var-table/var-table.component";
import { WebApiUrlService } from "./web-api-url.service";

@NgModule({
  declarations: [
    AppComponent,
    EmulateComponent,
    EditProgramComponent,
    EmuRequestFormComponent,
    VarTableComponent,
    HexPipe,
    TrimEnumPipe,
    TraceConfigsComponent,
    ProgramsComponent,
    EditWorkspaceProgramComponent,
    ListWorkspaceProgramComponent,
    SideNavComponent,
    SessionTableComponent,
    AboutComponent,
    AppToolbarComponent
  ],
  providers: [
    WebApiUrlService,
    TyphunixService,
    TraceAppService,
    WorkspaceService,
    MetaService,
    NgbTypeaheadConfig
  ],
  bootstrap: [AppComponent],
  imports: [
    MatExpansionModule,
    NgbAlertModule,
    AngularSplitModule,
    MatAutocompleteModule,
    MatPaginatorModule,
    MatProgressBarModule,
    MatChipsModule,
    MatSidenavModule,
    BrowserModule,
    BrowserAnimationsModule,
    MatFormFieldModule,
    MatSelectModule,
    MatInputModule,
    MatIconModule,
    MatDividerModule,
    MatButtonModule,
    CdkStepperModule,
    CdkTableModule,
    CdkTreeModule,
    MatExpansionModule,
    CdkVirtualScrollViewport,
    CdkAccordionModule,
    MatToolbarModule,
    MatBadgeModule,
    MatRadioModule,
    MatCheckboxModule,
    MatCardModule,
    FormsModule,
    ReactiveFormsModule,
    MatTableModule,
    FormsModule,
    ReactiveFormsModule,
    MatCheckboxModule,
    MatFormFieldModule,
    MatGridListModule,
    MatTooltipModule,
    MatFormFieldModule,
    ReactiveFormsModule,
    MatTabsModule,
    MatInputModule,
    MatPaginatorModule,
    MatSortModule,
    MatListModule,
    NgbModule,
    AppRoutingModule
  ]
})
export class AppModule {}
