"""Run the local API on loopback only."""

import argparse

import uvicorn

from ai_code_security_analyzer.api.app import create_app_from_env


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the loopback-only analyzer API")
    parser.parse_args()
    try:
        app = create_app_from_env()
    except RuntimeError as error:
        if str(error) in {"local_api_configuration_required", "local_api_configuration_invalid"}:
            raise SystemExit(str(error)) from None
        raise SystemExit("local_api_start_failed") from None
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8765,
        access_log=False,
        reload=False,
    )


if __name__ == "__main__":
    main()
