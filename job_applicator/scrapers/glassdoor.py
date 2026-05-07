from typing import List
from urllib.parse import quote_plus

from loguru import logger
from playwright.sync_api import TimeoutError as PWTimeout

from .base import BaseScraper, JobListing


class GlassdoorScraper(BaseScraper):
    BASE = "https://www.glassdoor.co.za"

    @property
    def platform_name(self) -> str:
        return "glassdoor"

    # ------------------------------------------------------------------ login

    def login(self) -> bool:
        try:
            self.page.goto(f"{self.BASE}/index.htm", wait_until="domcontentloaded")
            self.human_delay(2, 3)
            # Click Sign In
            try:
                self.page.click('button[data-test="sign-in-button"], a:has-text("Sign In")', timeout=5000)
                self.human_delay(1, 2)
            except Exception:
                pass

            self.page.fill('input[name="username"], input[id="inlineUserEmail"]',
                           self.platform_cfg["email"])
            self.human_delay(0.5, 1)
            try:
                self.page.click('button[type="submit"]', timeout=3000)
                self.human_delay(1, 2)
            except Exception:
                pass

            self.page.fill('input[type="password"], input[id="inlineUserPassword"]',
                           self.platform_cfg["password"])
            self.human_delay(0.5, 1)
            self.page.click('button[type="submit"]')
            self.page.wait_for_load_state("domcontentloaded", timeout=20_000)
            logger.info("Glassdoor login successful")
            return True
        except Exception as exc:
            logger.error(f"Glassdoor login failed: {exc}")
            return False

    # ------------------------------------------------------------------ search

    def search_jobs(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        keywords = " ".join(self.search_cfg.get("keywords", []))
        for location in self.search_cfg.get("locations", ["South Africa"]):
            jobs.extend(self._search(keywords, location))
        return jobs

    def _search(self, keywords: str, location: str) -> List[JobListing]:
        jobs: List[JobListing] = []
        url = (
            f"{self.BASE}/Job/jobs.htm"
            f"?sc.keyword={quote_plus(keywords)}"
            f"&locT=N&locId=all"
            f"&suggestCount=0&suggestChosen=false"
        )
        try:
            self.page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(3, 5)
            cards = self.page.query_selector_all('li[data-test="jobListing"], article.JobCard')
            logger.info(f"Glassdoor [{location}]: found {len(cards)} cards")
            for card in cards[:30]:
                job = self._parse_card(card)
                if job and self.matches_criteria(job.title):
                    jobs.append(job)
        except Exception as exc:
            logger.error(f"Glassdoor search error: {exc}")
        return jobs

    def _parse_card(self, card) -> JobListing | None:
        try:
            title_el = card.query_selector('[data-test="job-title"], .JobCard_jobTitle__GLyJ1')
            company_el = card.query_selector('[data-test="employer-name"], .EmployerProfile_compactEmployerName__LE242')
            location_el = card.query_selector('[data-test="emp-location"], .JobCard_location__N_iYE')
            link_el = card.query_selector('a[data-test="job-title"], a.JobCard_jobTitle__GLyJ1')
            if not title_el:
                return None
            href = link_el.get_attribute("href") if link_el else ""
            if href and href.startswith("/"):
                href = self.BASE + href
            return JobListing(
                title=title_el.inner_text().strip(),
                company=company_el.inner_text().strip() if company_el else "Unknown",
                location=location_el.inner_text().strip() if location_el else "",
                url=href,
                platform="glassdoor",
            )
        except Exception:
            return None

    # ------------------------------------------------------------------ apply

    def apply_to_job(self, job: JobListing) -> bool:
        dry_run = self.settings.get("dry_run", True)
        if dry_run:
            logger.info(f"[DRY RUN] Would open Glassdoor application: {job.title} @ {job.company}")
            return True
        try:
            self.page.goto(job.url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 4)
            apply_btn = self.page.query_selector(
                'button[data-test="applyButton"], a[data-test="applyButton"], '
                'button:has-text("Easy Apply"), button:has-text("Apply")'
            )
            if not apply_btn:
                logger.warning(f"Glassdoor: No apply button for {job.title}")
                return False
            apply_btn.click()
            self.human_delay(2, 3)

            # Glassdoor Easy Apply modal
            for step in range(8):
                self.human_delay(1.5, 2.5)
                file_inp = self.page.query_selector('input[type="file"]')
                if file_inp:
                    file_inp.set_input_files(self.profile.get("resume_path", "resume.pdf"))
                    self.human_delay(1, 2)

                submit_btn = self.page.query_selector(
                    'button:has-text("Submit"), button[data-test="submitButton"]'
                )
                next_btn = self.page.query_selector(
                    'button:has-text("Continue"), button:has-text("Next")'
                )
                if submit_btn:
                    submit_btn.click()
                    self.human_delay(2, 3)
                    logger.success(f"Applied to: {job.title} @ {job.company} (Glassdoor)")
                    return True
                elif next_btn:
                    next_btn.click()
                else:
                    break
        except Exception as exc:
            logger.error(f"Glassdoor apply error: {exc}")
        return False
