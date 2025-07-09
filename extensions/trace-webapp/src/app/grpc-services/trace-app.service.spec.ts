// SPDX-License-Identifier: BSD-2-Clause
import { TestBed } from '@angular/core/testing';

import { TraceAppService } from './trace-app.service';

describe('TraceAppService', () => {
  let service: TraceAppService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(TraceAppService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
