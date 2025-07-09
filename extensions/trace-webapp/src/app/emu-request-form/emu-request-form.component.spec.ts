// SPDX-License-Identifier: BSD-2-Clause
import { ComponentFixture, TestBed } from "@angular/core/testing";

import { EmuRequestFormComponent } from "./emu-request-form.component";

describe("EmuRequestFormComponent", () => {
  let component: EmuRequestFormComponent;
  let fixture: ComponentFixture<EmuRequestFormComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [EmuRequestFormComponent]
    });
    fixture = TestBed.createComponent(EmuRequestFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it("should create", () => {
    expect(component).toBeTruthy();
  });
});
