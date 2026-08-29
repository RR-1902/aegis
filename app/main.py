"""Minimal runtime entry point for AEGIS."""

from __future__ import annotations

import logging
import time

from app.pipeline import AEGISPipeline


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> int:
    configure_logging()
    pipeline = AEGISPipeline()

    if not pipeline.start():
        logging.getLogger(__name__).error("AEGIS runtime failed to start")
        return 1

    logging.getLogger(__name__).info("AEGIS runtime started; press Ctrl+C to stop")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("KeyboardInterrupt received; stopping AEGIS runtime")
    finally:
        pipeline.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
