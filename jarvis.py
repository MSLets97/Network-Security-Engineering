#!/usr/bin/env python3
"""
J.A.R.V.I.S. — Just A Rather Very Intelligent System
Entry point: CLI · Web · Voice
"""

import argparse
import sys
import os

# Ensure the repo root is on the path when run directly
sys.path.insert(0, os.path.dirname(__file__))


def main():
    parser = argparse.ArgumentParser(
        prog="jarvis",
        description="J.A.R.V.I.S. — Just A Rather Very Intelligent System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jarvis.py              # launch CLI
  python jarvis.py --voice      # CLI with voice I/O
  python jarvis.py --web        # launch web interface
  python jarvis.py --web --port 8080
        """,
    )

    parser.add_argument("--web",   action="store_true", help="Launch web interface instead of CLI")
    parser.add_argument("--voice", action="store_true", help="Enable voice I/O (CLI mode only)")
    parser.add_argument("--host",  default="0.0.0.0",   help="Web server host (default: 0.0.0.0)")
    parser.add_argument("--port",  type=int, default=5000, help="Web server port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")

    args = parser.parse_args()

    if not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY environment variable is not set.")
        print("  Set it via: export ANTHROPIC_API_KEY='sk-ant-...'")
        print("  Or create a .env file — see .env.example")
        sys.exit(1)

    if args.web:
        _launch_web(args)
    else:
        _launch_cli(args)


def _launch_web(args):
    from dotenv import load_dotenv
    load_dotenv()
    from jarvis.web.app import run_web
    print(f"[JARVIS] Web interface starting on http://{args.host}:{args.port}")
    run_web(host=args.host, port=args.port, debug=args.debug)


def _launch_cli(args):
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    from jarvis.cli import run_cli
    run_cli(voice_enabled=args.voice)


if __name__ == "__main__":
    main()
