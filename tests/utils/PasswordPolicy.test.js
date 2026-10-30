import { describe, expect, it } from 'vitest';
import TextEncoding from 'Utils/CodepageManager.js';
import { LOGIN_PASSWORD_FIELD_BYTES, MAX_LOGIN_PASSWORD_BYTES } from 'Utils/PasswordPolicy.js';

describe('Login password byte policy', () => {
	const cases = [
		['23 ASCII bytes', 'a'.repeat(23), true],
		['24 ASCII bytes', 'a'.repeat(24), false],
		['23 UTF-8 bytes', 'é'.repeat(10) + 'abc', true],
		['24 UTF-8 bytes', 'é'.repeat(12), false]
	];

	it('reserves one byte for the null terminator', () => {
		expect(LOGIN_PASSWORD_FIELD_BYTES).toBe(24);
		expect(MAX_LOGIN_PASSWORD_BYTES).toBe(23);
	});

	it.each(cases)('%s', (_description, password, expected) => {
		const bytes = TextEncoding.encode(password, 'utf-8').length;
		expect(bytes <= MAX_LOGIN_PASSWORD_BYTES).toBe(expected);
	});
});
