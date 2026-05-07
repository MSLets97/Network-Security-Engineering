from typing import List

import feedparser
import requests
from bs4 import BeautifulSoup
from loguru import logger

from .base import BaseScraper, JobListing

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"}


class WeWorkRemotelyScraper(BaseScraper):
    BASE = "https://weworkremotely.com"
    FEEDS = [
        f"{BASE}/categories/remote-devops-sysadmin-jobs.rss",
        f"{BASE}/categories/remote-programming-jobs.rss",
        f"{BASE}/categories/remote-full-stack-programming-jobs.rss",
    ]

    @property
    def platform_name(self) -> str:
        return "weworkremotely"

    def login(self) -> bool:
        return True

    # ------------------------------------------------------------------ search

    def search_jobs(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        seen: set = set()

        for feed_url in self.FEEDS:
            try:
                feed = feedparser.parse(feed_url)
                logger.info(f"We Work Remotely feed {feed_url}: {len(feed.entries)} entries")
                for entry in feed.entries[:30]:
                    title = entry.get("title", "")
                    company = entry.get("author", "Unknown")
                    url = entry.get("link", "")
                    if not url or url in seen:
                        continue
                    if self.matches_criteria(title):
                        seen.add(url)
                        jobs.append(JobListing(
                            title=title,
                            company=company,
                            location="Remote",
                            url=url,
                            platform="weworkremotely",
                        ))
            except Exception as exc:
                logger.error(f"We Work Remotely feed error: {exc}")

        # Fallback: scrape search page
        if not jobs:
            jobs.extend(self._scrape_search())

        return jobs

    def _scrape_search(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        try:
            resp = requests.get(f"{self.BASE}/remote-jobs/search?term=security", headers=HEADERS, timeout=20)
            soup = BeautifulSoup(resp.text, "lxml")
            for li in soup.select("ul.jobs > li"):
                title_el = li.select_one("span.title")
                company_el = li.select_one("span.company")
                link_el = li.select_one("a[href]")
                if not title_el or not link_el:
                    continue
                href = self.BASE + link_el["href"]
                title = title_el.get_text(strip=True)
                if self.matches_criteria(title):
                    jobs.append(JobListing(
                        title=title,
                        company=company_el.get_text(strip=True) if company_el else "Unknown",
                        location="Remote",
                        url=href,
                        platform="weworkremotely",
                    ))
        except Exception as exc:
            logger.error(f"We Work Remotely scrape error: {exc}")
        return jobs

    # ------------------------------------------------------------------ apply

    def apply_to_job(self, job: JobListing) -> bool:
        dry_run = self.settings.get("dry_run", True)
        if dry_run:
            logger.info(f"[DRY RUN] Would open WWR application: {job.title} @ {job.company}")
            return True
        try:
            self.page.goto(job.url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 3)
            apply_btn = self.page.query_selector('a.apply-link, a:has-text("Apply"), a:has-text("Apply for this position")')
            if apply_btn:
                apply_btn.click()
                self.human_delay(2, 3)
            logger.info(f"WWR: Opened apply page for {job.title}")
            return True
        except Exception as exc:
            logger.error(f"We Work Remotely apply error: {exc}")
            return False
