import type { TotpEnrollment } from '../domain/mfa-ports';

/**
 * `TotpEnrollment` of the contract. Explicit fields, nothing spread. It is the one response that
 * carries the TOTP secret (twice: in `uri` and in `secret`): it is shown once, so it must never be
 * logged or cached (`Cache-Control: no-store` comes from the pipeline).
 */
export type TotpEnrollmentDto = {
  readonly factorId: string;
  readonly uri: string;
  readonly secret: string;
  readonly qrCode: string;
};

export function toTotpEnrollmentDto(enrollment: TotpEnrollment): TotpEnrollmentDto {
  return {
    factorId: enrollment.factorId,
    uri: enrollment.uri,
    secret: enrollment.secret,
    qrCode: enrollment.qrCode,
  };
}
