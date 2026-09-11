import { config } from '../../config';

const UNIT_SECONDS: Record<string, number> = { s: 1, m: 60, h: 60 * 60, d: 24 * 60 * 60 };

/**
 * "15m" / "7d" style durations — the format JWT_*_EXPIRY is written in.
 *
 * One parser for every place a token lifetime is needed. The access cookie's
 * maxAge used to be a hardcoded 15 minutes beside a configurable JWT expiry,
 * so changing JWT_ACCESS_EXPIRY would have left the cookie dying before (or
 * after) the token it carries.
 */
export function parseDurationToSeconds(value: string, fallbackSeconds: number): number {
    const match = value.trim().match(/^(\d+)([smhd])$/);
    if (!match) return fallbackSeconds;
    return parseInt(match[1]!, 10) * UNIT_SECONDS[match[2]!]!;
}

export function accessTokenTtlMs(): number {
    return parseDurationToSeconds(config.JWT_ACCESS_EXPIRY, 15 * 60) * 1000;
}

export function refreshTokenTtlMs(): number {
    return parseDurationToSeconds(config.JWT_REFRESH_EXPIRY, 7 * 24 * 60 * 60) * 1000;
}
