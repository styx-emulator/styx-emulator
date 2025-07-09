import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ListWorkspaceProgramComponent } from './list-workspace-program.component';

describe('ListWorkspaceProgramComponent', () => {
  let component: ListWorkspaceProgramComponent;
  let fixture: ComponentFixture<ListWorkspaceProgramComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ListWorkspaceProgramComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ListWorkspaceProgramComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
