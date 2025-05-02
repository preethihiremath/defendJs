export const detectSQLInjection = (input) => {
    const patterns = [
        {
            pattern: /'/,
            message: "Possible SQL injection detected: Single quote character found.",
            fix: "Ensure that single quotes in user input are properly escaped or use parameterized queries."
        },
        {
            pattern: /(;|--|\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|RENAME|TRUNCATE|EXEC|UNION|DATABASE|TABLE|FROM|WHERE|JOIN|ON|INTO)\b)/i,
            message: "Possible SQL injection detected: SQL-specific syntax found.",
            fix: "Use parameterized queries or ORM libraries to avoid directly embedding user input in SQL commands."
        },
        {
            pattern: /\b(OR|AND)\b\s*(\d+|'.*?'|".*?")\s*=\s*(\d+|'.*?'|".*?")/i,
            message: "Possible SQL injection detected: Boolean condition found.",
            fix: "Validate and sanitize all user inputs to ensure they do not alter SQL logic. Prefer using ORM or query builders."
        },
        {
            pattern: /\b(WAITFOR|SLEEP|BENCHMARK|pg_sleep|pg_bench)\b\s*\(\s*\d+\s*\)/i,
            message: "Possible SQL injection detected: Time delay payload found.",
            fix: "Avoid executing time delay functions in SQL queries, and use database-specific security measures to prevent such injections."
        },
        {
            pattern: /\b(LOAD_FILE|INTO OUTFILE|INTO DUMPFILE|MASTER..XPSENDMAIL|UTL_HTTP.REQUEST|UTL_FILE|HTTPURITYPE|DBMS_LOB)\b/i,
            message: "Possible SQL injection detected: OAST payload found.",
            fix: "Restrict database permissions to prevent unauthorized file operations and network interactions. Use parameterized queries."
        },
        {
            pattern: /('(\s|\+|\-|\*|\/|%|=|<|>|!|\||&|\^|\|\|)+')/,
            message: "Possible SQL injection detected: Known SQL injection payload found.",
            fix: "Sanitize all user inputs and use parameterized queries or prepared statements to prevent injection."
        },
        {
            pattern: /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i,
            message: "Possible XSS attack detected: Script tag found.",
            fix: "Ensure user input is properly sanitized and encoded to prevent XSS attacks."
        },
        {
            pattern: /(\bUNION\b.*\bSELECT\b.*--|#)/i,
            message: "Possible SQL injection detected: UNION-based SQL injection attempt.",
            fix: "Use parameterized queries and validate all user inputs to avoid direct SQL execution."
        },
        {
            pattern: /(\bEXEC\b\s*\(\s*['"]?.*['"]?\s*\)|\bEXEC\b\s*\(\s*[^()]*\))/i,
            message: "Possible SQL injection detected: EXEC function call found.",
            fix: "Avoid using dynamic SQL execution functions and prefer parameterized queries."
        }
    ];

    for (const { pattern, message, fix } of patterns) {
        if (pattern.test(input)) {
            return {
                type: 'SQL Injection',
                // pattern: pattern.toString(),
                message,
                fix,
                input
            };
        }
    }
    return null;
};
