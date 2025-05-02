import { detectSQLInjection } from './scanner/sql/sqlInjection.js';
import { detectXSS } from './scanner/xss/xss.js';
import { detectCryptoFailure } from './scanner/crypto/detectCryptoFailure.js';
import { detectSSRF } from './scanner/ssrf/ssrf.js';
import { detectFailedLoginAttempts, detectConfigurationChanges, detectUnusualTraffic } from '../logger/securityLogging.js';
import chalk from 'chalk';

/**
 * Scans a given input for known security vulnerabilities (SQL Injection, XSS, Crypto Failures, and SSRF).
 * @param {string} input - The input string to be scanned for vulnerabilities.
 * @returns {Array} - An array of detected vulnerability objects, each containing the type and pattern.
 */
const scanForVulnerabilities = (input) => {
    const results = [];

    // Scan for SQL injection pattern
    const sqlInjectionResult = detectSQLInjection(input);
    if (sqlInjectionResult) {
        results.push(sqlInjectionResult);
    }

    // Scan for XSS pattern
    const xssResult = detectXSS(input);
    if (xssResult) {
        results.push(xssResult);
    }

    // Scan for Crypto failures
    const cryptoFailureResult = detectCryptoFailure(input);
    if (cryptoFailureResult) {
        results.push(cryptoFailureResult);
    }

    // Scan for SSRF
    const ssrfResult = detectSSRF(input);
    if (ssrfResult) {
        results.push(ssrfResult);
    }

    return results;
};

/**
 * Middleware function to scan incoming HTTP requests for security vulnerabilities.
 * It checks query parameters and request body for patterns of SQL Injection, XSS, Crypto Failures, and SSRF.
 * If vulnerabilities are detected, they are logged to the console.
 * 
 * @param {object} req - The HTTP request object.
 * @param {object} res - The HTTP response object.
 * @param {function} next - The next middleware function in the stack.
 */
export default (req, res, next) => {
    // Combine all query parameters and request body into a single array of inputs
    const inputs = [...Object.values(req.query), ...Object.values(req.body)];
    console.log(inputs); //to be removed after testing

    // Iterate over each input to scan for vulnerabilities
    inputs.forEach(input => {
        if (typeof input === 'string') {
            const detectedVulnerabilities = scanForVulnerabilities(input);
            detectedVulnerabilities.forEach(vulnerability => {
                console.warn(chalk.yellow(`WARN: Vulnerability detected: ${vulnerability.message} `));
                console.warn(chalk.yellow(`Input: ${vulnerability.input}`));
                console.warn(chalk.green(`Suggested fix: ${vulnerability.fix}`));
            });
        }
    });

    // Example: Detect failed login attempts
    const username = req.body.username;
    const loginSuccess = false; // Replace with actual login success logic
    if (username) {
        detectFailedLoginAttempts(username, loginSuccess);
    }

    // Example: Detect unusual traffic patterns
    const ip = req.ip;
    const endpoint = req.originalUrl;
    detectUnusualTraffic(ip, endpoint);

    // Example: Detect configuration changes
    const configName = 'exampleConfig';
    const oldValue = 'oldValue';
    const newValue = 'newValue'; // Replace with actual configuration change logic
    detectConfigurationChanges(configName, oldValue, newValue);

    // Proceed to the next middleware or route handler
    next();
};
