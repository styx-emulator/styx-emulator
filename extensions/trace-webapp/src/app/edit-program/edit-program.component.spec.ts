import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EditProgramComponent } from './edit-program.component';

describe('EditProgramComponent', () => {
  let component: EditProgramComponent;
  let fixture: ComponentFixture<EditProgramComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EditProgramComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(EditProgramComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
