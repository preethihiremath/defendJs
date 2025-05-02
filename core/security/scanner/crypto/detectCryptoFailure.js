
import crypto from 'crypto';
import CryptoJS from 'crypto-js';
import chalk from 'chalk';
import { cryptoFailurePatterns } from './patterns.js';

/**
 * Scans input for known cryptographic weaknesses.
 * @param {string} input - Input source code or string to check.
 * @returns {Array|null} Array of findings, or null if none found.
 */
export const detectCryptoFailure = (input) => {
    const results = [];

    cryptoFailurePatterns.forEach(({ pattern, message, fix }) => {
        if (pattern.test(input)) {
            results.push({
                type: 'Cryptographic Failure',
                message,
                fix,
                input
            });
        }
    });

    return results.length ? results : null;
};
