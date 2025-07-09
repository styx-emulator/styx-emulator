// SPDX-License-Identifier: BSD-2-Clause
import { TrimEnumPipe } from './trim-enum.pipe';

describe('TrimEnumPipe', () => {
  it('create an instance', () => {
    const pipe = new TrimEnumPipe();
    expect(pipe).toBeTruthy();
  });
});
