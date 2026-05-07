from typing import List

import requests
from bs4 import BeautifulSoup
from loguru import logger

from .base import BaseScraper, JobListing

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"}


class RemoteCoScraper(BaseScraper):
    BASE = "https://remote.co"

    @property
    def platform_name(self) -> str:
        return "remoteco"

    def login(self) -> bool:
        return True   # No login required

    # ------------------------------------------------------------------ search

    def search_jobs(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        for keyword in self.search_cfg.get("keywords", []):
            jobs.extend(self._search(keyword))
        return self._deduplicate(jobs)

    def _search(self, keyword: str) -> List[JobListing]:
        jobs: List[JobListing] = []
        slug = keyword.lower().replace(" ", "-")
        urls_to_try = [
            f"{self.BASE}/remote-jobs/search/?search_keywords={keyword.replace(' ', '+')}",
            f"{self.BASE}/remote-jobs/it/",
            f"{self.BASE}/remote-jobs/information-security/",
        ]
        for url in urls_to_try[:1]:
            try:
                resp = requests.get(url, headers=HEADERS, timeout=20)
                soup = BeautifulSoup(resp.text, "lxml")
                cards = soup.select(".job_listing, li.job")
                logger.info(f"Remote.co [{keyword}]: found {len(cards)} listings")
                for card in cards[:20]:
                    job = self._parse_card(card)
                    if job and self.matches_criteria(job.title):
                        jobs.append(job)
            except Exception as exc:
                logger.error(f"Remote.co search error: {exc}")
        return jobs

    def _parse_card(self, card) -> JobListing | None:
        try:
            title_el = card.select_one(".position, h3, .job-title")
            company_el = card.select_one(".company, .company_name")
            link_el = card.select_one("a[href]")
            if not title_el or not link_el:
                return None
            href = link_el["href"]
            if href.startswith("/"):
                href = self.BASE + href
            return JobListing(
                title=title_el.get_text(strip=True),
                company=company_el.get_text(strip=True) if company_el else "Unknown",
                location="Remote",
                url=href,
                platform="remoteco",
            )
        except Exception:
            return None

    @staticmethod
    def _deduplicate(jobs: List[JobListing]) -> List[JobListing]:
        seen = set()
        unique = []
        for j in jobs:
            if j.url not in seen:
                seen.add(j.url)
                unique.append(j)
        return unique

    # ------------------------------------------------------------------ apply

    def apply_to_job(self, job: JobListing) -> bool:
        """Remote.co redirects to company apply pages — open in browser for user to complete."""
        dry_run = self.settings.get("dry_run", True)
        if dry_run:
            logger.info(f"[DRY RUN] Would open Remote.co application: {job.title} @ {job.company}")
            return True
        try:
            self.page.goto(job.url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 3)
            apply_btn = self.page.query_selector(
                'a:has-text("Apply"), a:has-text("Apply Now"), a.apply_button'
            )
            if apply_btn:
                apply_btn.click()
                self.human_delay(2, 3)
            logger.info(f"Remote.co: Opened application page for {job.title} — complete manually if redirected to company site")
            return True
        except Exception as exc:
            logger.error(f"Remote.co apply error: {exc}")
            return False
