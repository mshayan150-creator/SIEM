"""Initialize new local settings or preserve existing deployment secrets."""
from pathlib import Path


def main() -> None:
    path = Path(__file__).resolve().parent.parent / '.env.local'
    if not path.exists():
        from init_local import main as initialize
        initialize()
        return
    print('Existing .env.local preserved. Use ops.admin to create individual accounts; legacy shared keys are ignored.')


if __name__ == '__main__':
    main()
