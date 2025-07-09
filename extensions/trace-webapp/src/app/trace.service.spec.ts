// SPDX-License-Identifier: BSD-2-Clause
import { TestBed } from "@angular/core/testing";

import { TraceService } from "./trace.service";

describe("TraceService", () => {
  let service: TraceService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(TraceService);
  });

  it("should be created", () => {
    expect(service).toBeTruthy();
  });
});
