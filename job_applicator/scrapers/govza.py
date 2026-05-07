"""
South African Government Job Scrapers
- DPSA (Department of Public Service and Administration) circular vacancies
- e-Recruitment portal (e-recruitment.gov.za)
"""

from typing import List

import requests
from bs4 import BeautifulSoup
from loguru import logger

from .base import BaseScraper, JobListing

HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"}

DPSA_URL = "https://www.dpsa.gov.za/dpsa2g/vacancies.asp"
ERECRUITMENT_URL = "https://e-recruitment.gov.za"
ETENDERS_URL = "https://www.etenders.gov.za"


class GovZAScraper(BaseScraper):

    @property
    def platform_name(self) -> str:
        return "govza"

    def login(self) -> bool:
        return True   # DPSA is publicly accessible; e-recruitment requires registration

    # ------------------------------------------------------------------ search

    def search_jobs(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        jobs.extend(self._scrape_dpsa())
        jobs.extend(self._scrape_erecruitment())
        return jobs

    # ......................................................... DPSA circular

    def _scrape_dpsa(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        try:
            resp = requests.get(DPSA_URL, headers=HEADERS, timeout=30)
            soup = BeautifulSoup(resp.text, "lxml")

            # DPSA lists vacancies as links to PDF circulars and a summary table
            rows = soup.select("table tr")
            if not rows:
                # Try alternative structure
                links = soup.select('a[href*="vacancy"], a[href*="circular"]')
                for link in links[:20]:
                    title = link.get_text(strip=True)
                    if title and self.matches_criteria(title):
                        href = link.get("href", "")
                        if href.startswith("/"):
                            href = "https://www.dpsa.gov.za" + href
                        jobs.append(JobListing(
                            title=title,
                            company="South African Government",
                            location="South Africa",
                            url=href or DPSA_URL,
                            platform="govza_dpsa",
                        ))
                if not jobs:
                    logger.info("DPSA: No matching vacancies in current circular")
                return jobs

            for row in rows[1:]:   # Skip header
                cols = row.select("td")
                if len(cols) < 3:
                    continue
                title = cols[0].get_text(strip=True)
                department = cols[1].get_text(strip=True) if len(cols) > 1 else "Government"
                closing = cols[-1].get_text(strip=True)
                link_el = row.select_one("a[href]")
                href = ""
                if link_el:
                    href = link_el.get("href", "")
                    if href.startswith("/"):
                        href = "https://www.dpsa.gov.za" + href
                if title and self.matches_criteria(title):
                    jobs.append(JobListing(
                        title=title,
                        company=department or "SA Government Department",
                        location="South Africa",
                        url=href or DPSA_URL,
                        platform="govza_dpsa",
                    ))
            logger.info(f"DPSA: found {len(jobs)} matching vacancies")
        except Exception as exc:
            logger.error(f"DPSA scrape error: {exc}")
        return jobs

    # .................................................. e-Recruitment portal

    def _scrape_erecruitment(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        try:
            resp = requests.get(f"{ERECRUITMENT_URL}/Home/PublicVacancies", headers=HEADERS, timeout=30)
            soup = BeautifulSoup(resp.text, "lxml")
            rows = soup.select("table tr, .vacancy-item, .job-item")
            logger.info(f"e-Recruitment: found {len(rows)} rows")
            for row in rows[1:]:
                title_el = row.select_one("td:first-child, .vacancy-title, h4")
                dept_el = row.select_one("td:nth-child(2), .department")
                link_el = row.select_one("a[href]")
                if not title_el:
                    continue
                title = title_el.get_text(strip=True)
                if not title or not self.matches_criteria(title):
                    continue
                href = ""
                if link_el:
                    href = link_el.get("href", "")
                    if href.startswith("/"):
                        href = ERECRUITMENT_URL + href
                jobs.append(JobListing(
                    title=title,
                    company=dept_el.get_text(strip=True) if dept_el else "SA Government",
                    location="South Africa",
                    url=href or ERECRUITMENT_URL,
                    platform="govza_erecruitment",
                ))
        except Exception as exc:
            logger.error(f"e-Recruitment scrape error: {exc}")
        return jobs

    # ------------------------------------------------------------------ apply

    def apply_to_job(self, job: JobListing) -> bool:
        """
        Government applications require official Z83 forms and supporting docs.
        The app opens the listing for the user and logs the instructions.
        """
        dry_run = self.settings.get("dry_run", True)
        logger.info(
            f"[GOV ZA] {job.title} @ {job.company}\n"
            f"  URL: {job.url}\n"
            f"  NOTE: Government jobs require a completed Z83 form + certified copies of qualifications.\n"
            f"  Download Z83 from: https://www.dpsa.gov.za/dpsa2g/documents/vacancies/z83.pdf"
        )
        if dry_run:
            logger.info(f"[DRY RUN] Would open: {job.url}")
            return True
        try:
            self.page.goto(job.url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 4)
            # For e-recruitment portal, attempt to click Apply
            apply_btn = self.page.query_selector(
                'a:has-text("Apply"), button:has-text("Apply"), a:has-text("Apply Online")'
            )
            if apply_btn:
                apply_btn.click()
                self.human_delay(2, 3)
                logger.info(f"e-Recruitment: Opened application for {job.title} — fill Z83 form manually")
            return True
        except Exception as exc:
            logger.error(f"Gov ZA apply error: {exc}")
            return False
