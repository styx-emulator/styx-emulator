import { ComponentFixture, TestBed } from "@angular/core/testing";

import { EmulateComponent } from "./emulate.component";

describe("EmulateComponent", () => {
  let component: EmulateComponent;
  let fixture: ComponentFixture<EmulateComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [EmulateComponent]
    });
    fixture = TestBed.createComponent(EmulateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it("should create", () => {
    expect(component).toBeTruthy();
  });
});
