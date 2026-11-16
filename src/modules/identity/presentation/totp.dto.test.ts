import { describe, expect, it } from 'vitest';
import { toTotpEnrollmentDto } from './totp.dto';

describe('toTotpEnrollmentDto (TotpEnrollment)', () => {
  it('lists exactly the four fields of the contract, whatever else the domain object carries', () => {
    const enrollment = {
      factorId: '33333333-3333-4333-8333-333333333333',
      uri: 'otpauth://totp/Rastreador:ceo?secret=JBSWY3DPEHPK3PXP',
      secret: 'JBSWY3DPEHPK3PXP',
      qrCode: 'data:image/svg+xml;utf-8,<svg/>',
      internal: 'must not leak',
    };

    const dto = toTotpEnrollmentDto(enrollment);

    expect(Object.keys(dto).sort()).toEqual(['factorId', 'qrCode', 'secret', 'uri']);
    expect(dto).toEqual({
      factorId: enrollment.factorId,
      uri: enrollment.uri,
      secret: enrollment.secret,
      qrCode: enrollment.qrCode,
    });
  });
});
