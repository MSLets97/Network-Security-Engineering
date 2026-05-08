#!/usr/bin/env python3
"""
Job Applicator — automatically searches multiple job boards and applies on your behalf.

Usage:
    python main.py                    # Run with config.yaml (dry_run: true by default)
    python main.py --apply            # Override dry_run and actually submit applications
    python main.py --report           # Show stats from the local database
    python main.py --platform linkedin # Run only LinkedIn
"""

import argparse
import sys
import time
from pathlib import Path

import yaml
from loguru import logger
from playwright.sync_api import sync_playwright
from rich.console import Console
from rich.table import Table

import db
from scrapers import (
    GlassdoorScraper,
    GovZAScraper,
    IndeedScraper,
    LinkedInScraper,
    PNetScraper,
    RemoteCoScraper,
    WeWorkRemotelyScraper,
)

console = Console()

SCRAPER_MAP = {
    "linkedin": LinkedInScraper,
    "indeed": IndeedScraper,
    "glassdoor": GlassdoorScraper,
    "remoteco": RemoteCoScraper,
    "weworkremotely": WeWorkRemotelyScraper,
    "pnet": PNetScraper,
    "govza": GovZAScraper,
}


def load_config(path: str = "config.yaml") -> dict:
    config_path = Path(path)
    if not config_path.exists():
        logger.error(f"Config file not found: {path}")
        sys.exit(1)
    with open(config_path) as f:
        return yaml.safe_load(f)


def setup_logging(config: dict):
    level = config.get("settings", {}).get("log_level", "INFO")
    output_dir = Path(config.get("settings", {}).get("output_dir", "output"))
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.remove()
    logger.add(sys.stderr, level=level, colorize=True,
               format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | {message}")
    logger.add(output_dir / "applicator.log", level="DEBUG", rotation="10 MB")


def print_report():
    stats = db.get_stats()
    recent = db.get_recent_jobs(20)

    table = Table(title="Application Stats")
    table.add_column("Status", style="cyan")
    table.add_column("Count", justify="right", style="magenta")
    for status, count in stats.items():
        table.add_row(status, str(count))
    console.print(table)

    if recent:
        t2 = Table(title="Recent Jobs Found")
        t2.add_column("Title")
        t2.add_column("Company")
        t2.add_column("Platform")
        t2.add_column("Status")
        t2.add_column("Found At")
        for job in recent:
            t2.add_row(
                job["title"], job["company"], job["platform"],
                job["status"], job["found_at"][:16]
            )
        console.print(t2)


def run(config: dict, only_platform: str | None = None):
    settings = config["settings"]
    dry_run = settings.get("dry_run", True)
    max_apps = settings.get("max_applications_per_run", 15)
    delay = settings.get("delay_between_applications", 45)
    headless = settings.get("headless", False)

    if dry_run:
        console.print("[bold yellow]DRY RUN MODE — no applications will be submitted[/bold yellow]")
    else:
        console.print("[bold red]LIVE MODE — applications will be SUBMITTED[/bold red]")

    resume_path = Path(config["profile"].get("resume_path", "resume.pdf"))
    if not dry_run and not resume_path.exists():
        logger.error(f"Resume file not found: {resume_path}. Please update resume_path in config.yaml")
        sys.exit(1)

    db.init_db()
    applied_count = 0

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=headless,
            args=["--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800},
        )
        # Mask webdriver flag to reduce bot detection
        ctx.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        page = ctx.new_page()

        for platform_name, ScraperClass in SCRAPER_MAP.items():
            if only_platform and platform_name != only_platform:
                continue
            platform_cfg = config["platforms"].get(platform_name, {})
            if not platform_cfg.get("enabled", True):
                logger.info(f"Skipping {platform_name} (disabled in config)")
                continue
            if applied_count >= max_apps:
                logger.info(f"Reached max applications limit ({max_apps})")
                break

            console.rule(f"[bold blue]{platform_name.upper()}")
            scraper = ScraperClass(config, page)

            # Login
            try:
                if not scraper.login():
                    logger.warning(f"{platform_name}: Login failed, skipping")
                    continue
            except Exception as exc:
                logger.error(f"{platform_name}: Login exception: {exc}")
                continue

            # Search
            try:
                jobs = scraper.search_jobs()
                logger.info(f"{platform_name}: {len(jobs)} matching jobs found")
            except Exception as exc:
                logger.error(f"{platform_name}: Search exception: {exc}")
                continue

            # Save all found jobs to DB
            for job in jobs:
                db.save_job(
                    title=job.title, company=job.company,
                    location=job.location, url=job.url,
                    platform=job.platform, salary=job.salary,
                    job_type=job.job_type,
                )

            # Apply
            for job in jobs:
                if applied_count >= max_apps:
                    break
                if db.job_exists(job.url) and _already_applied(job.url):
                    logger.debug(f"Already applied to {job.title}, skipping")
                    continue

                console.print(f"  [cyan]{job.title}[/cyan] @ [green]{job.company}[/green] ({job.location})")
                console.print(f"  [dim]{job.url}[/dim]")

                try:
                    success = scraper.apply_to_job(job)
                    if success:
                        db.mark_applied(job.url)
                        applied_count += 1
                        logger.success(f"Applied ({applied_count}/{max_apps}): {job.title}")
                    else:
                        db.mark_failed(job.url)
                except Exception as exc:
                    logger.error(f"Apply exception for {job.title}: {exc}")
                    db.mark_failed(job.url, str(exc))

                if applied_count < max_apps and not dry_run:
                    logger.debug(f"Waiting {delay}s before next application...")
                    time.sleep(delay)

        browser.close()

    console.rule("[bold green]Run Complete")
    print_report()


def _already_applied(url: str) -> bool:
    """Check if we have already applied to this job URL."""
    import sqlite3
    from pathlib import Path
    db_path = Path("output/jobs.db")
    if not db_path.exists():
        return False
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT status FROM jobs WHERE url = ?", (url,))
    row = c.fetchone()
    conn.close()
    return row is not None and row[0] == "applied"


def main():
    parser = argparse.ArgumentParser(description="Automated Job Applicator")
    parser.add_argument("--config", default="config.yaml", help="Path to config YAML file")
    parser.add_argument("--apply", action="store_true", help="Actually submit applications (overrides dry_run in config)")
    parser.add_argument("--report", action="store_true", help="Show database report and exit")
    parser.add_argument("--platform", choices=list(SCRAPER_MAP.keys()), help="Run only one platform")
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config)

    if args.apply:
        config["settings"]["dry_run"] = False

    if args.report:
        db.init_db()
        print_report()
        return

    run(config, only_platform=args.platform)


if __name__ == "__main__":
    main()
