// SPDX-License-Identifier: BSD-2-Clause
import { TestBed } from "@angular/core/testing";

import { WebApiUrlService } from "./web-api-url.service";

describe("WebApiUrlService", () => {
  let service: WebApiUrlService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(WebApiUrlService);
  });

  it("should be created", () => {
    expect(service).toBeTruthy();
  });
});
