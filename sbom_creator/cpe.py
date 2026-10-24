"""CPE 2.3 (Common Platform Enumeration) resolution for NVD matching."""
import re
from typing import Optional, Dict, Tuple

# Mapping of normalized library names/aliases to (vendor, product)
# Focused on C/C++ libraries where PURL resolution to NVD CVEs is often ambiguous
CPE_LOOKUP: Dict[str, Tuple[str, str]] = {
    # Networking / Transfer
    "curl": ("haxx", "curl"),
    "libcurl": ("haxx", "curl"),
    # Document / OCR / Imaging (e.g. tesseract stack)
    "lept": ("leptonica", "leptonica"),
    "leptonica": ("leptonica", "leptonica"),
    "liblept": ("leptonica", "leptonica"),
    "tesseract": ("tesseract-ocr", "tesseract"),
    "libtesseract": ("tesseract-ocr", "tesseract"),
    "libarchive": ("libarchive", "libarchive"),
    "archive": ("libarchive", "libarchive"),
    "png": ("libpng", "libpng"),
    "libpng": ("libpng", "libpng"),
    "jpeg": ("ijg", "libjpeg"),
    "libjpeg": ("ijg", "libjpeg"),
    "tiff": ("libtiff", "libtiff"),
    "libtiff": ("libtiff", "libtiff"),
    "webp": ("webmproject", "libwebp"),
    "libwebp": ("webmproject", "libwebp"),
    "opencv": ("opencv", "opencv"),
    "cairo": ("cairographics", "cairo"),
    "freetype": ("freetype", "freetype"),
    "freetype2": ("freetype", "freetype"),
    "harfbuzz": ("harfbuzz_project", "harfbuzz"),
    "pango": ("pango", "pango"),
    # Unicode / Text
    "icu": ("icu-project", "international_components_for_unicode"),
    "icu-uc": ("icu-project", "international_components_for_unicode"),
    "icu-i18n": ("icu-project", "international_components_for_unicode"),
    "icu-io": ("icu-project", "international_components_for_unicode"),
    # Crypto / Security
    "openssl": ("openssl", "openssl"),
    "libssl": ("openssl", "openssl"),
    "libcrypto": ("openssl", "openssl"),
    # Compression
    "zlib": ("zlib", "zlib"),
    "z": ("zlib", "zlib"),
    "libz": ("zlib", "zlib"),
    "bzip2": ("bzip", "bzip2"),
    "libbz2": ("bzip", "bzip2"),
    "xz": ("tukaani", "xz"),
    "liblzma": ("tukaani", "xz"),
    "zstd": ("facebook", "zstandard"),
    "libzstd": ("facebook", "zstandard"),
    # Database
    "sqlite": ("sqlite", "sqlite"),
    "sqlite3": ("sqlite", "sqlite"),
    "libsqlite3": ("sqlite", "sqlite"),
    # XML / Parsing / JSON
    "libxml2": ("xmlsoft", "libxml2"),
    "xml2": ("xmlsoft", "libxml2"),
    "expat": ("libexpat", "expat"),
    "libexpat": ("libexpat", "expat"),
    "nlohmann-json": ("nlohmann", "json"),
    "json-c": ("json-c_project", "json-c"),
    # Utilities / Runtime
    "glib": ("gnome", "glib"),
    "glib-2.0": ("gnome", "glib"),
    "boost": ("boost", "boost"),
    "libuv": ("libuv", "libuv"),
    "uv": ("libuv", "libuv"),
    "protobuf": ("google", "protobuf"),
    "pcre": ("pcre", "pcre"),
    "pcre2": ("pcre", "pcre2"),
    "pcre2-8": ("pcre", "pcre2"),
    "fmt": ("fmt", "fmt"),
    "spdlog": ("gabime", "spdlog"),
    "gtest": ("google", "googletest"),
    "googletest": ("google", "googletest"),
}

def resolve_cpe23(name: str, version: Optional[str] = None) -> Optional[str]:
    """Resolve component name and version into a CPE 2.3 formatted string."""
    clean_name = name.lower().strip()
    # Normalize common prefix/suffix like lib... or -devel
    lookup_key = clean_name.removesuffix("-devel").removesuffix("-dev")
    
    vendor_product = CPE_LOOKUP.get(lookup_key)
    if not vendor_product and lookup_key.startswith("lib"):
        vendor_product = CPE_LOOKUP.get(lookup_key[3:])

    if not vendor_product:
        return None

    vendor, product = vendor_product
    ver = version.strip() if version and version.lower() != "unknown" else "*"
    # Sanitize version for CPE (escape colons or special chars if any)
    ver = re.sub(r"[^a-zA-Z0-9.\-_]", "", ver) or "*"

    return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
