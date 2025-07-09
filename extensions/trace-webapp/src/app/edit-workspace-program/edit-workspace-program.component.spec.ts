import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EditWorkspaceProgramComponent } from './edit-workspace-program.component';

describe('EditWorkspaceProgramComponent', () => {
  let component: EditWorkspaceProgramComponent;
  let fixture: ComponentFixture<EditWorkspaceProgramComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [EditWorkspaceProgramComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(EditWorkspaceProgramComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
