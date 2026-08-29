from security.file_policy import validate_read_path


def read_file(file_path: str) -> str:
    """
    Read a file only if it is inside an allowed directory.
    """

    try:
        # Security check before accessing the file
        target_file = validate_read_path(file_path)

    except PermissionError as e:
        return f"[SECURITY BLOCK] {e}"

    if not target_file.exists():
        return f"Error: File not found: {file_path}"

    if not target_file.is_file():
        return f"Error: Not a file: {file_path}"

    try:
        return target_file.read_text(encoding="utf-8")

    except Exception as e:
        return f"Error reading file: {e}"