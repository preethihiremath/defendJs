
export const cryptoFailurePatterns = [
    {
        pattern: /crypto\.createCipher/,
        message: "Insecure cryptographic function: crypto.createCipher",
        fix: "Use crypto.createCipheriv with AES-GCM instead.",
    },
    {
        pattern: /\b(MD5|SHA1)\b/,
        message: "Weak hash algorithm: MD5 or SHA1",
        fix: "Use SHA-256, SHA-3, or bcrypt.",
    },
    {
        pattern: /Math\.random\(\)/,
        message: "Insecure random generator: Math.random()",
        fix: "Use crypto.randomBytes() instead.",
    },
    {
        pattern: /\b(ECDSA|DSA)\b/,
        message: "Weak signature algorithm: ECDSA or DSA",
        fix: "Use modern ECC or RSA with strong key lengths.",
    },
    {
        pattern: /AES-ECB/,
        message: "Insecure AES mode: ECB",
        fix: "Use AES-GCM or AES-CBC with authenticated encryption.",
    },
    {
        pattern: /\b(base64|atob|btoa)\b/,
        message: "Potentially insecure encoding: base64/atob/btoa",
        fix: "Prefer Buffer or Base64url for safer encoding.",
    },
    {
        pattern: /CryptoJS\.MD5\(/,
        message: "Weak hash from CryptoJS: MD5",
        fix: "Use CryptoJS.SHA256 or SHA3.",
    },
    {
        pattern: /crypto\.createHash\(['"]md5['"]\)/i,
        message: "Node.js hash using MD5",
        fix: "Switch to SHA256 or stronger.",
    },
    {
        pattern: /crypto\.randomBytes\(/,
        message: "Use of crypto.randomBytes (check context)",
        fix: "Ensure secure usage with proper size and handling.",
    },
];
