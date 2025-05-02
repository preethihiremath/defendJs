const patterns = [
    {
        pattern: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        message: "Possible XSS attack detected: Script tags found.",
        fix: "Sanitize user input to remove or encode HTML tags, or use a library such as DOMPurify to sanitize HTML."
    },
    {
        pattern: /(onerror|onload|onclick|onmouseover|onfocus|oninput|onchange)=["'].*?["']/gi,
        message: "Possible XSS attack detected: Inline event handlers found.",
        fix: "Disallow or properly escape inline event handlers in user input."
    }
];

export const detectXSS = (input) => {


    for (const { pattern, message, fix } of patterns) {
        if (pattern.test(input)) {
            return {
                type: 'XSS',
                // pattern: pattern.toString(),
                message,
                fix,
                input
            };
        }
    }
    return null;
};
