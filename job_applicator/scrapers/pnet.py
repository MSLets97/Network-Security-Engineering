from typing import List
from urllib.parse import quote_plus

from loguru import logger
from playwright.sync_api import TimeoutError as PWTimeout

from .base import BaseScraper, JobListing


class PNetScraper(BaseScraper):
    BASE = "https://www.pnet.co.za"

    @property
    def platform_name(self) -> str:
        return "pnet"

    # ------------------------------------------------------------------ login

    def login(self) -> bool:
        try:
            self.page.goto(f"{self.BASE}/login", wait_until="domcontentloaded")
            self.human_delay(2, 3)
            self.page.fill('input[name="email"], input[id*="email"]', self.platform_cfg["email"])
            self.human_delay(0.5, 1)
            self.page.fill('input[name="password"], input[id*="password"]', self.platform_cfg["password"])
            self.human_delay(0.5, 1)
            self.page.click('button[type="submit"], input[type="submit"]')
            self.page.wait_for_load_state("domcontentloaded", timeout=20_000)
            logger.info("PNet login successful")
            return True
        except Exception as exc:
            logger.error(f"PNet login failed: {exc}")
            return False

    # ------------------------------------------------------------------ search

    def search_jobs(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        keywords = self.search_cfg.get("keywords", [])
        for keyword in keywords[:3]:   # Limit to avoid too many searches
            jobs.extend(self._search(keyword))
        return self._deduplicate(jobs)

    def _search(self, keyword: str) -> List[JobListing]:
        jobs: List[JobListing] = []
        url = f"{self.BASE}/jobs/{quote_plus(keyword.lower().replace(' ', '-'))}"
        try:
            self.page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 4)
            cards = self.page.query_selector_all(
                'article.job-card, div[data-job-id], .job-listing-item, [class*="JobCard"]'
            )
            logger.info(f"PNet [{keyword}]: found {len(cards)} cards")
            for card in cards[:25]:
                job = self._parse_card(card)
                if job and self.matches_criteria(job.title):
                    jobs.append(job)
        except Exception as exc:
            logger.error(f"PNet search error: {exc}")
        return jobs

    def _parse_card(self, card) -> JobListing | None:
        try:
            title_el = card.query_selector('h2, h3, [class*="title"], [class*="Title"]')
            company_el = card.query_selector('[class*="company"], [class*="Company"], [class*="employer"]')
            location_el = card.query_selector('[class*="location"], [class*="Location"]')
            link_el = card.query_selector("a[href]")
            if not title_el or not link_el:
                return None
            href = link_el.get_attribute("href") or ""
            if href.startswith("/"):
                href = self.BASE + href
            return JobListing(
                title=title_el.inner_text().strip(),
                company=company_el.inner_text().strip() if company_el else "Unknown",
                location=location_el.inner_text().strip() if location_el else "South Africa",
                url=href,
                platform="pnet",
            )
        except Exception:
            return None

    @staticmethod
    def _deduplicate(jobs: List[JobListing]) -> List[JobListing]:
        seen = set()
        result = []
        for j in jobs:
            if j.url not in seen:
                seen.add(j.url)
                result.append(j)
        return result

    # ------------------------------------------------------------------ apply

    def apply_to_job(self, job: JobListing) -> bool:
        dry_run = self.settings.get("dry_run", True)
        if dry_run:
            logger.info(f"[DRY RUN] Would apply on PNet: {job.title} @ {job.company}")
            return True
        try:
            self.page.goto(job.url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 4)

            apply_btn = self.page.query_selector(
                'button:has-text("Apply"), a:has-text("Apply"), '
                'button:has-text("Apply now"), a:has-text("Apply now")'
            )
            if not apply_btn:
                logger.warning(f"PNet: No apply button for {job.title}")
                return False
            apply_btn.click()
            self.human_delay(2, 3)

            # PNet apply form
            resume_uploaded = False
            for step in range(6):
                self.human_delay(1.5, 2.5)

                # Upload resume / CV
                if not resume_uploaded:
                    file_inp = self.page.query_selector('input[type="file"]')
                    if file_inp:
                        file_inp.set_input_files(self.profile.get("resume_path", "resume.pdf"))
                        resume_uploaded = True
                        self.human_delay(1, 2)

                # Fill text fields
                for inp in self.page.query_selector_all('input[type="text"], input[type="email"], input[type="tel"]'):
                    try:
                        label_el = self.page.query_selector(f'label[for="{inp.get_attribute("id")}"]')
                        label_text = label_el.inner_text() if label_el else inp.get_attribute("placeholder") or ""
                        answer = self.fill_common_field(label_text)
                        if answer and not inp.input_value():
                            self.slow_type(inp, answer)
                    except Exception:
                        pass

                submit_btn = self.page.query_selector('button:has-text("Submit"), button[type="submit"]')
                next_btn = self.page.query_selector('button:has-text("Next"), button:has-text("Continue")')

                if submit_btn:
                    submit_btn.click()
                    self.human_delay(2, 3)
                    logger.success(f"Applied to: {job.title} @ {job.company} (PNet)")
                    return True
                elif next_btn:
                    next_btn.click()
                else:
                    break

        except Exception as exc:
            logger.error(f"PNet apply error: {exc}")
        return False
