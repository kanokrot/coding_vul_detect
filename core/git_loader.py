import os
import tempfile
import shutil
import subprocess

# ── Constants ─────────────────────────────────────────────────────────────────
CLONE_TIMEOUT_SECONDS = 60          # max time to wait for git clone
MAX_FILE_SIZE_BYTES   = 512 * 1024  # 512 KB per file — skip generated/minified files
MAX_CODE_LENGTH       = 50_000      # truncation limit (chars) — aligned with scanner.py


def clone_and_read_repo(git_url: str) -> list[tuple[str, str]]:
    """
    Clone a Git repository (shallow, depth=1) and return a list of
    (relative_path, code_content) tuples for all .c/.cpp/.h/.hpp files.

    URL normalisation is handled upstream in scanner.py — this function
    trusts the URL it receives and does NOT re-process it.

    Raises
    ------
    Exception
        Re-raises with original message if clone fails, preserving context.
    """
    scanned_files = []
    temp_dir      = tempfile.mkdtemp()

    # FIX: removed duplicate URL normalisation — scanner.py already handles this
    # for all supported hosts (GitHub, GitLab, Bitbucket). Doing it again here
    # with a GitHub-only regex would silently mangle GitLab/Bitbucket URLs.
    print(f"DEBUG: Cloning -> {git_url}")

    try:
        # ── Clone with timeout so a slow/huge repo can't hang Gradio ─────────
        result = subprocess.run(
            ["git", "clone", "--depth", "1", git_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS   # FIX: was unbounded
        )

        if result.returncode != 0:
            raise Exception(f"Git clone failed:\n{result.stderr.strip()}")

        # ── Walk repo, skip .git internals ────────────────────────────────────
        for root, dirs, files in os.walk(temp_dir):
            # Prune .git so we never descend into it
            if '.git' in dirs:
                dirs.remove('.git')

            for filename in files:
                if not filename.endswith(('.c', '.cpp', '.h', '.hpp')):
                    continue

                full_path = os.path.join(root, filename)

                # FIX: skip oversized files (generated code, minified headers, etc.)
                try:
                    file_size = os.path.getsize(full_path)
                except OSError:
                    continue

                if file_size > MAX_FILE_SIZE_BYTES:
                    print(f"⚠️ Skipping {filename} — too large ({file_size // 1024} KB)")
                    continue

                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Truncate to match scanner.py MAX_CODE_LENGTH behaviour
                    if len(content) > MAX_CODE_LENGTH:
                        print(f"⚠️ Truncated {filename} to {MAX_CODE_LENGTH} chars")
                        content = content[:MAX_CODE_LENGTH]

                    relative_path = os.path.relpath(full_path, temp_dir)
                    scanned_files.append((relative_path, content))

                except Exception as e:
                    # FIX: log instead of silently swallowing — helps debug encoding issues
                    print(f"⚠️ Could not read {filename}: {e}")

    except subprocess.TimeoutExpired:
        # FIX: surface timeout clearly so Gradio can show a useful message
        raise Exception(
            f"Git clone timed out after {CLONE_TIMEOUT_SECONDS}s. "
            "The repository may be too large or the network too slow."
        )

    # FIX: removed bare `raise Exception(str(e))` wrapper that was eating tracebacks
    # Exceptions from clone failure propagate naturally from the try block above.

    finally:
        # Always clean up temp dir — ignore errors (handles Windows file-lock edge cases)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    return scanned_files