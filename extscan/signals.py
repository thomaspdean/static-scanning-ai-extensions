"""Signal tables for the Stage 3 scan: group -> name -> compiled regex.

These are leads, not proof: a regex hit says the code mentions a capability. Runtime-built
URLs, string concatenation and obfuscation will evade them.
"""
from __future__ import annotations

import re

I = re.IGNORECASE


def _c(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


URL_RE = _c(r"""\b(?:https?|wss?)://[^\s'"`<>\\)\]}|^]+""")

# Network sinks (calls that can send data out of the browser).
NETWORK_SINKS = {
    "fetch": _c(r"\bfetch\s*\("),
    "xhr": _c(r"\bnew\s+XMLHttpRequest\b|\bXMLHttpRequest\s*\("),
    "send_beacon": _c(r"\bsendBeacon\s*\("),
    "websocket": _c(r"\bnew\s+WebSocket\s*\("),
    "event_source": _c(r"\bnew\s+EventSource\s*\("),
    "image_beacon": _c(r"\bnew\s+Image\s*\(\s*\)"),
    "http_client_lib": _c(r"\baxios\s*[.(]|\$\.(?:ajax|post|getJSON)\s*\(|\bky\s*\.\s*(?:get|post)\s*\("),
    "native_messaging": _c(r"\bchrome\.runtime\.(?:connectNative|sendNativeMessage)\b"),
    "web_request_listener": _c(r"\bchrome\.webRequest\.on\w+"),
}

# Reading page content or reaching into hidden / nested surfaces.
DOM_HARVEST = {
    "page_text": _c(r"\bdocument\.(?:body|documentElement)\.(?:innerText|textContent)\b"),
    "page_html": _c(r"\bdocument\.(?:body|documentElement)\.(?:innerHTML|outerHTML)\b"),
    "selection": _c(r"\bgetSelection\s*\(\s*\)"),
    "form_inputs": _c(r"""querySelectorAll\(\s*['"][^'"]*\b(?:input|textarea|select|form)\b|\bdocument\.forms\b|getElementsByTagName\(\s*['"](?:input|textarea|form)['"]"""),
    "password_field": _c(r"""input\[type=["']?password|type\s*[=:]\s*\\?["']password\\?["']"""),
    "hidden_input": _c(r"""input\[type=["']?hidden|type\s*[=:]\s*\\?["']hidden\\?["']"""),
    "computed_style": _c(r"\bgetComputedStyle\s*\("),
    "shadow_root_access": _c(r"\.shadowRoot\b"),
    "attach_shadow": _c(r"\battachShadow\s*\("),   # usually the extension's own UI
    "iframe_access": _c(r"\.contentDocument\b|\.contentWindow\.document\b|querySelectorAll\(\s*['\"]iframe"),
    "mutation_observer": _c(r"\bnew\s+MutationObserver\s*\("),
    "document_cookie": _c(r"\bdocument\.cookie\b"),
    "page_url_title": _c(r"\bdocument\.(?:title|URL|referrer)\b"),
    "content_extractor": _c(r"\bnew\s+Readability\b|\bTurndownService\b"),
    "screenshot": _c(r"\bcaptureVisibleTab\b|\bgetDisplayMedia\b|\btabCapture\.capture\b"),
    "clipboard_read": _c(r"\bclipboard\.read(?:Text)?\s*\("),
}

# Sensitive-data access and hard-coded credentials. Secret-shaped hits are redacted.
SENSITIVE = {
    "cookies_api": _c(r"\bchrome\.cookies\.(?:get|getAll|set|remove)\b"),
    "history_api": _c(r"\bchrome\.history\.(?:search|getVisits)\b"),
    "identity_api": _c(r"\bchrome\.identity\.(?:getAuthToken|getProfileUserInfo|launchWebAuthFlow)\b"),
    "bookmarks_api": _c(r"\bchrome\.bookmarks\.\w+"),
    "downloads_api": _c(r"\bchrome\.downloads\.(?:download|search)\b"),
    "management_api": _c(r"\bchrome\.management\.(?:getAll|get|setEnabled)\b"),
    "tabs_query": _c(r"\bchrome\.tabs\.query\s*\("),
    "extension_storage_read": _c(r"\bchrome\.storage\.(?:sync|local|session)\.get\b"),
    "sensitive_field_names": _c(r"""(?<![A-Za-z0-9_$])(?:ssn|SSN|cvv|CVV|cvc|CVC|iban|IBAN|creditCard|cardNumber)(?![A-Za-z0-9_$])|(?i:\b(?:social[-_]?security|credit[-_]card|card[-_]?number|cc-number|cc-csc|routing[-_]?number)\b|autocomplete\W{1,3}(?:cc-|current-password|new-password))"""),
    "key_openai": _c(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"),
    "key_google": _c(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "key_aws": _c(r"\bAKIA[0-9A-Z]{16}\b"),
    "key_github": _c(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "key_slack": _c(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "hardcoded_secret_assign": _c(r"""\b(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-./+=]{20,}["']""", I),
    "bearer_literal": _c(r"\bBearer\s+[A-Za-z0-9._~+/-]{24,}"),
}
REDACT = {"key_openai", "key_google", "key_aws", "key_github", "key_slack", "hardcoded_secret_assign", "bearer_literal"}

# Dynamic / remote code execution.
REMOTE_CODE = {
    "eval": _c(r"(?<![.\w$])eval\s*\((?!\?)"),   # (?!\?) skips regex alternations like eval(?:cmd)?
    "new_function": _c(r"""\bnew\s+Function\s*\((?!\s*["']return this)|(?<![.\w$])Function\s*\(\s*["'`](?!return this)"""),
    "string_timer": _c(r"""\bset(?:Timeout|Interval)\s*\(\s*["'`]"""),
    "create_script_element": _c(r"""createElement\(\s*["']script["']\s*\)"""),
    "script_src_remote": _c(r"""<script[^>]+src\s*=\s*["']?(?:https?:)?//""", I),
    "execute_script": _c(r"\bchrome\.scripting\.(?:executeScript|registerContentScripts)\b|\bchrome\.tabs\.executeScript\b|\bchrome\.userScripts\.\w+"),
    "main_world_injection": _c(r"""\bworld\s*:\s*["']MAIN["']"""),
    "import_scripts_remote": _c(r"""\bimportScripts\s*\(\s*["']https?:|\bimport\s*\(\s*["']https?:"""),
    "wasm": _c(r"\bWebAssembly\.(?:instantiate|compile)(?:Streaming)?\s*\("),
}

# Obfuscation indicators. The escape-run signals also match regex character classes and
# i18n tables, so they are informational and never decide the obfuscation level.
OBFUSCATION = {
    "packer": _c(r"eval\(function\(p,a,c,k,e"),
    "hex_identifiers": _c(r"\b_0x[a-f0-9]{4,6}\b"),
    "hex_escape_run": _c(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
    "unicode_escape_run": _c(r"(?:\\u[0-9a-fA-F]{4}){8,}"),
    "long_base64": _c(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{300,}={0,2}"),
    "atob": _c(r"\batob\s*\("),
    "from_char_code_run": _c(r"fromCharCode\s*\((?:[^()]*,){7,}"),
}
# long_base64 hits preceded by these are embedded images/fonts/etc., not code.
BASE64_BENIGN_PREFIX = _c(r"(?:base64,|data:)\s*$")

GROUPS = {
    "network_sinks": NETWORK_SINKS,
    "dom_harvest": DOM_HARVEST,
    "sensitive": SENSITIVE,
    "remote_code": REMOTE_CODE,
    "obfuscation": OBFUSCATION,
}
# These decide the per-extension obfuscation level.
OBFUSCATION_SIGNALS = ("packer", "hex_identifiers", "from_char_code_run")
# Common in ordinary UI/framework code: reported, but excluded from group totals.
LOW_VALUE = {"computed_style", "attach_shadow", "mutation_observer", "extension_storage_read",
             "tabs_query", "wasm", "atob", "hex_escape_run", "unicode_escape_run", "long_base64"}
