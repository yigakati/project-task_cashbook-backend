import { AppError } from '../errors/AppError';

export const EAST_AFRICAN_CURRENCY_CODES = ['UGX', 'KES', 'TZS', 'RWF', 'BIF', 'SSP', 'ETB'] as const;
export type EastAfricanCurrencyCode = typeof EAST_AFRICAN_CURRENCY_CODES[number];

/**
 * Currencies a workspace may be denominated in: the East-African set the
 * product was built around, plus USD for businesses that trade in dollars.
 * The no-FX rule is unchanged — a workspace still gets exactly one base
 * currency; this only widens which one that may be.
 */
export const SUPPORTED_BASE_CURRENCY_CODES = [...EAST_AFRICAN_CURRENCY_CODES, 'USD'] as const;
export type SupportedBaseCurrencyCode = typeof SUPPORTED_BASE_CURRENCY_CODES[number];

/**
 * The home currency of each country the product serves. A user's country,
 * captured at signup, decides the currency their personal workspace is born
 * in — and through it, the wallets they are seeded with.
 */
export const COUNTRY_CURRENCIES: Record<string, SupportedBaseCurrencyCode> = {
    UG: 'UGX',
    KE: 'KES',
    TZ: 'TZS',
    RW: 'RWF',
    BI: 'BIF',
    SS: 'SSP',
    ET: 'ETB',
    US: 'USD',
};

/** The workspace currency for an ISO 3166-1 alpha-2 country; anything else
 *  falls back to the product's home base (UGX), preserving the behavior of
 *  signups that predate the country question. */
export function currencyForCountry(country: string | null | undefined): SupportedBaseCurrencyCode {
    const code = (country || '').trim().toUpperCase();
    return COUNTRY_CURRENCIES[code] ?? 'UGX';
}

/** Normalize ISO-like currency codes (UGX, USD, KES). */
export function normalizeCurrency(code: string | null | undefined, fallback = 'UGX'): string {
    const c = (code || fallback).trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(c)) {
        throw new AppError(
            `Invalid currency code "${code}". Use a 3-letter ISO code (e.g. UGX, USD).`,
            400,
            'INVALID_CURRENCY',
        );
    }
    return c;
}

export function assertSupportedBaseCurrency(code: string | null | undefined): SupportedBaseCurrencyCode {
    const normalized = normalizeCurrency(code);
    if (!(SUPPORTED_BASE_CURRENCY_CODES as readonly string[]).includes(normalized)) {
        throw new AppError(
            `Unsupported workspace base currency "${normalized}". Use one of: ${SUPPORTED_BASE_CURRENCY_CODES.join(', ')}.`,
            400,
            'UNSUPPORTED_BASE_CURRENCY',
        );
    }
    return normalized as SupportedBaseCurrencyCode;
}

/**
 * Hard block: no FX conversion. Money amounts may only combine when codes match.
 */
export function assertSameCurrency(
    expected: string,
    actual: string | null | undefined,
    context: string,
): void {
    const exp = normalizeCurrency(expected);
    const act = normalizeCurrency(actual, exp);
    if (exp !== act) {
        throw new AppError(
            `Currency mismatch (${context}): expected ${exp}, got ${act}. Cross-currency amounts are not converted.`,
            400,
            'CURRENCY_MISMATCH',
        );
    }
}

export function currenciesEqual(a: string | null | undefined, b: string | null | undefined): boolean {
    try {
        return normalizeCurrency(a) === normalizeCurrency(b);
    } catch {
        return false;
    }
}
