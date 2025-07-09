// SPDX-License-Identifier: BSD-2-Clause
import { TestBed } from "@angular/core/testing";

import { SessionMgrService } from "./session-mgr.service";

describe("SessionMgrService", () => {
  let service: SessionMgrService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(SessionMgrService);
  });

  it("should be created", () => {
    expect(service).toBeTruthy();
  });
});
