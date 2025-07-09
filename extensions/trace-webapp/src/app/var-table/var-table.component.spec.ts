// SPDX-License-Identifier: BSD-2-Clause
import { ComponentFixture, TestBed } from "@angular/core/testing";

import { VarTableComponent } from "./var-table.component";

describe("VarTableComponent", () => {
  let component: VarTableComponent;
  let fixture: ComponentFixture<VarTableComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [VarTableComponent]
    });
    fixture = TestBed.createComponent(VarTableComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it("should create", () => {
    expect(component).toBeTruthy();
  });
});
