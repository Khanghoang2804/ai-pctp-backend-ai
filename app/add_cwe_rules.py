import re
from pathlib import Path

config_path = Path("/home/nemo/code/ast/app/service/ConfigScanLayer1.py")
content = config_path.read_text(encoding="utf-8")

NEW_RULES = """    # ── CWE-918: SERVER-SIDE REQUEST FORGERY (SSRF) ────────────────────────
    {
        "id": "SEC091",
        "name": "SSRF (Python requests/urllib)",
        "severity": "critical",
        "category": "ssrf",
        "pattern": r"(?i)(requests\.(get|post|put|delete)|urllib\.request\.urlopen)\s*\(\s*.*(request\.|request_data|params|args|kwargs|url)",
        "description": "Thực hiện HTTP Request tới URL do người dùng cung cấp (SSRF).",
        "recommendation": "Kiểm tra URL có nằm trong whitelist không trước khi gọi, chặn dải IP nội bộ.",
    },
    {
        "id": "SEC092",
        "name": "SSRF (Node.js axios/fetch/request)",
        "severity": "critical",
        "category": "ssrf",
        "pattern": r"(?i)(axios|fetch|request\.get)\s*\(\s*.*req\.(body|query|params)\.",
        "description": "Gọi HTTP request tới URL lấy từ input của request (Node.js).",
        "recommendation": "Cần filter và whitelist URL kỹ càng.",
    },
    {
        "id": "SEC093",
        "name": "SSRF (PHP curl/file_get_contents)",
        "severity": "critical",
        "category": "ssrf",
        "pattern": r"(?i)(curl_setopt.*CURLOPT_URL|file_get_contents)\s*\(.*\$_(GET|POST|REQUEST)",
        "description": "Chỉ định URL curl hoặc file_get_contents bằng dữ liệu ngoài (PHP).",
        "recommendation": "Phải xác thực URL qua filter_var với FILTER_VALIDATE_URL.",
    },

    # ── CWE-601: OPEN REDIRECT ─────────────────────────────────────────────
    {
        "id": "SEC094",
        "name": "Open Redirect (Express/Node.js)",
        "severity": "high",
        "category": "open_redirect",
        "pattern": r"(?i)res\.redirect\s*\(\s*req\.(query|body)\.",
        "description": "Chuyển hướng người dùng dựa vào tham số đầu vào không được kiểm chứng.",
        "recommendation": "Chỉ redirect tới các đường dẫn tương đối hoặc các URL đã được whitelist.",
    },
    {
        "id": "SEC095",
        "name": "Open Redirect (Python/Django/Flask)",
        "severity": "high",
        "category": "open_redirect",
        "pattern": r"(?i)(redirect|HttpResponseRedirect)\s*\(\s*request\.(GET|POST|args|form)",
        "description": "Chuyển hướng HTTP dựa vào dữ liệu request (Python).",
        "recommendation": "Sử dụng url_has_allowed_host_and_scheme() (Django) hoặc kiểm tra tương tự.",
    },
    {
        "id": "SEC096",
        "name": "Open Redirect (PHP header)",
        "severity": "high",
        "category": "open_redirect",
        "pattern": r"(?i)header\s*\(\s*['\"]Location:\s*['\"]\s*\.\s*\$_(GET|POST|REQUEST)",
        "description": "Redirect người dùng qua hàm header() bằng dữ liệu ngoài.",
        "recommendation": "Cố định hostname hoặc dùng whitelist.",
    },

    # ── CWE-942: OVERLY PERMISSIVE CORS POLICY ─────────────────────────────
    {
        "id": "SEC097",
        "name": "CORS Allow-Origin Wildcard",
        "severity": "high",
        "category": "misconfiguration",
        "pattern": r"(?i)Access-Control-Allow-Origin\s*['\"]?\s*:\s*['\"]?\*['\"]?",
        "description": "CORS Policy cho phép mọi domain (*).",
        "recommendation": "Chỉ allow origin cụ thể cần thiết.",
    },
    {
        "id": "SEC098",
        "name": "CORS Dynamic Origin Reflection",
        "severity": "critical",
        "category": "misconfiguration",
        "pattern": r"(?i)Access-Control-Allow-Origin.*?req\.headers\.origin",
        "description": "Phản xạ trực tiếp header Origin của người dùng làm Allow-Origin.",
        "recommendation": "Kiểm tra Origin có thuộc danh sách an toàn không rồi mới phản xạ.",
    },

    # ── CWE-614 / CWE-1004: INSECURE COOKIE FLAGS ──────────────────────────
    {
        "id": "SEC099",
        "name": "Insecure Cookie (secure: false)",
        "severity": "medium",
        "category": "misconfiguration",
        "pattern": r"(?i)(res\.cookie.*secure\s*:\s*false|setcookie.*false)",
        "description": "Cookie chứa session nhưng không có cờ Secure.",
        "recommendation": "Cài đặt cờ Secure=true để cookie chỉ truyền qua HTTPS.",
    },
    {
        "id": "SEC100",
        "name": "Insecure Cookie (httpOnly: false)",
        "severity": "medium",
        "category": "misconfiguration",
        "pattern": r"(?i)(res\.cookie.*httpOnly\s*:\s*false|setcookie.*false)",
        "description": "Cookie có thể bị truy cập bởi JavaScript (thiếu HttpOnly).",
        "recommendation": "Cài đặt cờ HttpOnly=true cho session cookie.",
    },

    # ── CWE-338: CRYPTOGRAPHICALLY WEAK PRNG ───────────────────────────────
    {
        "id": "SEC101",
        "name": "Weak PRNG (Math.random)",
        "severity": "medium",
        "category": "weak_crypto",
        "pattern": r"\bMath\.random\s*\(",
        "description": "Sử dụng Math.random() cho các tác vụ tạo token/password/crypto.",
        "recommendation": "Sử dụng crypto.randomBytes() hoặc window.crypto.getRandomValues().",
    },
    {
        "id": "SEC102",
        "name": "Weak PRNG (PHP rand/mt_rand)",
        "severity": "medium",
        "category": "weak_crypto",
        "pattern": r"\b(rand|mt_rand|uniqid)\s*\(",
        "description": "Các hàm random cơ bản của PHP không an toàn cho bảo mật.",
        "recommendation": "Sử dụng random_int() hoặc random_bytes().",
    },

    # ── CWE-319: CLEARTEXT TRANSMISSION OF SENSITIVE INFO ──────────────────
    {
        "id": "SEC103",
        "name": "Cleartext Protocols (FTP/Telnet/HTTP)",
        "severity": "high",
        "category": "insecure_network",
        "pattern": r"(?i)['\"](ftp|telnet|http)://[a-zA-Z0-9.\-]+['\"]",
        "description": "Sử dụng giao thức không mã hóa (FTP, Telnet, HTTP) để truyền dữ liệu.",
        "recommendation": "Chuyển sang SFTP, SSH, HTTPS.",
        "whitelist_pattern": r"(?i)['\"]http://(localhost|127\.0\.0\.1|0\.0\.0\.0|[^']*\.xml|[^']*\.dtd)['\"]",
    },

    # ── CWE-312: CLEARTEXT STORAGE OF SENSITIVE INFO ───────────────────────
    {
        "id": "SEC104",
        "name": "Sensitive Info in LocalStorage",
        "severity": "high",
        "category": "sensitive_storage",
        "pattern": r"(?i)localStorage\.setItem\s*\(\s*['\"](password|token|secret|key|jwt)['\"]",
        "description": "Lưu trữ thông tin nhạy cảm vào localStorage.",
        "recommendation": "Sử dụng HttpOnly Cookies để lưu token, không lưu trong LocalStorage vì dễ bị XSS đánh cắp.",
    },

    # ── CWE-119 / CWE-120: BUFFER COPY WITHOUT CHECKING SIZE ───────────────
    {
        "id": "SEC105",
        "name": "C/C++ scanf without width",
        "severity": "critical",
        "category": "buffer_overflow",
        "pattern": r"(?i)\b(scanf|fscanf|sscanf)\s*\(\s*['\"][^'\"]*%s",
        "description": "Sử dụng %s trong scanf không giới hạn chiều dài gây Buffer Overflow.",
        "recommendation": "Sử dụng format string giới hạn độ dài (ví dụ: %255s).",
    },
    {
        "id": "SEC106",
        "name": "C/C++ memcpy/memset overlapping",
        "severity": "high",
        "category": "buffer_overflow",
        "pattern": r"\b(memcpy|memset)\s*\([^,]+,[^,]+,\s*(strlen\([^)]+\)|[a-zA-Z_0-9]+)\)",
        "description": "Cẩn trọng khi dùng memcpy/memset với tham số size động có nguy cơ tràn bộ đệm.",
        "recommendation": "Đảm bảo size không vượt quá kích thước cấp phát của dest buffer.",
    },

    # ── CWE-1333: INEFFICIENT REGULAR EXPRESSION (ReDoS) ───────────────────
    {
        "id": "SEC107",
        "name": "Regex Denial of Service (ReDoS)",
        "severity": "high",
        "category": "dos",
        "pattern": r"([a-zA-Z0-9.\-_\\s]\+)\+\/?",
        "description": "Cú pháp Regex lặp lồng nhau có thể gây Regex Denial of Service.",
        "recommendation": "Hạn chế sử dụng (+)+ hoặc (*)* trong Regex, dùng các thư viện an toàn.",
    },

    # ── CWE-754: IMPROPER CHECK FOR UNUSUAL CONDITIONS ─────────────────────
    {
        "id": "SEC108",
        "name": "Missing Error Handling (Empty Catch)",
        "severity": "low",
        "category": "misconfiguration",
        "pattern": r"catch\s*\([^\)]*\)\s*\{\s*\}",
        "description": "Khối try-catch bắt lỗi nhưng để trống (Empty Catch Block).",
        "recommendation": "Nên log lỗi hoặc xử lý một cách cụ thể thay vì swallow Exception.",
    },

    # ── CWE-326: INADEQUATE ENCRYPTION STRENGTH ────────────────────────────
    {
        "id": "SEC109",
        "name": "Weak RSA Key Size (< 2048)",
        "severity": "high",
        "category": "weak_crypto",
        "pattern": r"(?i)KeyPairGenerator\.getInstance\s*\(\s*['\"]RSA['\"]\s*\).*?\.initialize\s*\(\s*(512|1024)\s*\)",
        "description": "Tạo cặp khóa RSA với độ dài yếu (512 hoặc 1024 bit).",
        "recommendation": "Sử dụng độ dài khóa tối thiểu 2048 bit.",
    },

    # ── CWE-190: INTEGER OVERFLOW/WRAPAROUND ───────────────────────────────
    {
        "id": "SEC110",
        "name": "C/C++ Integer Overflow Functions",
        "severity": "medium",
        "category": "integer_overflow",
        "pattern": r"\b(atoi|atol|atoll)\s*\(",
        "description": "Sử dụng atoi/atol không an toàn khi tràn số, kết quả không xác định.",
        "recommendation": "Sử dụng strtol, strtoll và kiểm tra errno (ERANGE).",
    }
]"""

# Thay thế dấu ] cuối cùng bằng khối rules mới
new_content = content.replace("    }\n]", NEW_RULES)

config_path.write_text(new_content, encoding="utf-8")
print("Added 20 new rules successfully!")
