import { TestBed } from '@angular/core/testing';

import { TyphunixService } from './typhunix.service';

describe('TyphunixService', () => {
  let service: TyphunixService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(TyphunixService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
