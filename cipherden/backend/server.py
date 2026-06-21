from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run(
        "cipherden.backend.app:app",
        host="127.0.0.1",
        port=8765,
        workers=1,
    )


if __name__ == "__main__":
    main()
