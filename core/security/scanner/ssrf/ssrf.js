// ssrf.js
export const detectSSRF = (input) => {
    const patterns = [
        {
            pattern: /(127\.0\.0\.1|localhost|::1)/i,
            message: "Potential SSRF detected: Attempt to access localhost or loopback address.",
            fix: "Ensure that user inputs are not used to construct URLs for internal resources. Validate and sanitize all inputs."
        },
        {
            pattern: /(169\.254\.\d+\.\d+)/i,
            message: "Potential SSRF detected: Attempt to access link-local address (169.254.x.x).",
            fix: "Block access to internal network addresses by validating and sanitizing all user inputs."
        },
        {
            pattern: /(172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)/i,
            message: "Potential SSRF detected: Attempt to access private network address (172.16.x.x - 172.31.x.x).",
            fix: "Ensure that user inputs do not include URLs for internal resources. Validate and sanitize all inputs."
        },
        {
            pattern: /(192\.168\.\d+\.\d+)/i,
            message: "Potential SSRF detected: Attempt to access private network address (192.168.x.x).",
            fix: "Block access to internal network addresses by validating and sanitizing all user inputs."
        },
        {
            pattern: /(10\.\d+\.\d+\.\d+)/i,
            message: "Potential SSRF detected: Attempt to access private network address (10.x.x.x).",
            fix: "Ensure that user inputs are not used to construct URLs for internal resources. Validate and sanitize all inputs."
        },
        {
            pattern: /(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/i,
            message: "Potential SSRF detected: Attempt to access an IP address.",
            fix: "Verify the necessity of direct IP access. Implement access controls and input validation to prevent unauthorized access."
        },
        {
            pattern: /(file:\/\/)/i,
            message: "Potential SSRF detected: Attempt to access local file system.",
            fix: "Block access to file URIs and ensure user inputs do not include URLs for local resources."
        },
    ];

    const results = [];

    patterns.forEach(({ pattern, message, fix }) => {
        if (pattern.test(input)) {
            results.push({
                type: 'SSRF',
                message,
                fix,
                input
            });
        }
    });

    return results.length > 0 ? results : null;
};
