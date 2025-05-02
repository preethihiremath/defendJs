import fs from 'fs';
import path from 'path';
import chalk from 'chalk';

// Log file path
const logFilePath = process.env.SECURITY_LOG_PATH || path.resolve('core/logger/security.log');


/**
 * Log security events to a file.
 * @param {string} eventType - The type of security event.
 * @param {string} message - The message describing the security event.
 */
export const logSecurityEvent = (eventType, message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `${timestamp} [${eventType}] ${message}\n`;

    // Append log message to the security log file
    fs.appendFileSync(logFilePath, logMessage, 'utf8');

    // Also log to the console with color coding
    switch (eventType) {
        case 'WARNING':
            console.warn(chalk.yellow(logMessage));
            break;
        case 'ERROR':
            console.error(chalk.red(logMessage));
            break;
        case 'INFO':
        default:
            console.log(chalk.blue(logMessage));
            break;
    }
};

/**
 * Detect multiple failed login attempts.
 * @param {string} username - The username attempting to log in.
 * @param {boolean} success - Whether the login attempt was successful.
 */
export const detectFailedLoginAttempts = (username, success) => {
    const attempts = failedLoginAttempts[username] || { count: 0, timestamp: Date.now() };

    if (!success) {
        attempts.count += 1;
        if (attempts.count >= 3 && (Date.now() - attempts.timestamp) <= 60000) {
            logSecurityEvent('WARNING', `Multiple failed login attempts detected for user: ${username}`);
        }
    } else {
        attempts.count = 0;
    }

    attempts.timestamp = Date.now();
    failedLoginAttempts[username] = attempts;
};

const failedLoginAttempts = {};

/**
 * Detect configuration changes.
 * @param {string} configName - The name of the configuration that was changed.
 * @param {string} oldValue - The old value of the configuration.
 * @param {string} newValue - The new value of the configuration.
 */
export const detectConfigurationChanges = (configName, oldValue, newValue) => {
    if (oldValue !== newValue) {
        logSecurityEvent('INFO', `Configuration change detected for ${configName}: ${oldValue} -> ${newValue}`);
    }
};

/**
 * Detect unusual traffic patterns.
 * @param {string} ip - The IP address of the incoming request.
 * @param {string} endpoint - The endpoint being accessed.
 */
export const detectUnusualTraffic = (ip, endpoint) => {
    const access = trafficLogs[ip] || { count: 0, timestamp: Date.now() };

    access.count += 1;
    if (access.count >= 100 && (Date.now() - access.timestamp) <= 60000) {
        logSecurityEvent('WARNING', `Unusual traffic pattern detected from IP: ${ip} to endpoint: ${endpoint}`);
    }

    access.timestamp = Date.now();
    trafficLogs[ip] = access;
};

const trafficLogs = {};
