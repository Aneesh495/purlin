#!/usr/bin/env python3
import os
import sys

def check_file(filepath):
    errors = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for idx, line in enumerate(f, 1):
            if '\u2014' in line:
                errors.append((idx, "Unicode em dash (U+2014) detected", line.strip()))
            # check for double hyphens used as em dash with surrounding spaces e.g. " -- "
            if ' -- ' in line and not line.strip().startswith(('--', '//', '#', '/*')):
                # allowed if it is command line flag separator, but flag it if text
                pass
    return errors

def main():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    has_err = False
    for root, dirs, files in os.walk(repo_root):
        if '.git' in dirs:
            dirs.remove('.git')
        if '.koka' in dirs:
            dirs.remove('.koka')
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in ['.kk', '.md', '.txt', '.py', '.c', '.h', '.html', '.js', '.css', '.json']:
                path = os.path.join(root, file)
                errs = check_file(path)
                if errs:
                    has_err = True
                    rel = os.path.relpath(path, repo_root)
                    for line_no, msg, line in errs:
                        print(f"ERROR in {rel}:{line_no}: {msg}\n  Line: {line}")
    if has_err:
        print("\nVerification FAILED: Em dashes detected!")
        sys.exit(1)
    else:
        print("Verification PASSED: Zero em dashes detected across repository.")

if __name__ == '__main__':
    main()
