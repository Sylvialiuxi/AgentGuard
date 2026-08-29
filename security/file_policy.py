from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

ALLOWED_DIRECTORIES = [
    (PROJECT_ROOT / "data" / "logs").resolve(),
    (PROJECT_ROOT / "data" / "public").resolve(),
]


def validate_read_path(file_path: str):

    target = (PROJECT_ROOT / "data" / file_path).resolve()

    for allowed_dir in ALLOWED_DIRECTORIES:
        try:
            target.relative_to(allowed_dir)
            return target
        except ValueError:
            continue

    raise PermissionError(
        f"Access denied: {file_path} is outside allowed directories."
    )