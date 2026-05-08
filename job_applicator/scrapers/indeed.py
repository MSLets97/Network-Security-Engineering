from typing import List
from urllib.parse import quote_plus

from loguru import logger
from playwright.sync_api import TimeoutError as PWTimeout

from .base import BaseScraper, JobListing


class IndeedScraper(BaseScraper):

    @property
    def platform_name(self) -> str:
        return "indeed"

    @property
    def _base_url(self) -> str:
        domain = self.platform_cfg.get("country_domain", "za")
        return f"https://{domain}.indeed.com"

    # ------------------------------------------------------------------ login

    def login(self) -> bool:
        """Indeed login is optional; search works without it."""
        email = self.platform_cfg.get("email", "")
        password = self.platform_cfg.get("password", "")
        if not email or not password:
            logger.info("Indeed: no credentials provided, proceeding without login")
            return True
        try:
            self.page.goto(f"{self._base_url}/account/login", wait_until="domcontentloaded")
            self.human_delay(2, 3)
            self.page.fill('input[name="__email"]', email)
            self.human_delay(0.5, 1)
            self.page.click('button[type="submit"]')
            self.human_delay(1, 2)
            self.page.fill('input[name="__password"]', password)
            self.human_delay(0.5, 1)
            self.page.click('button[type="submit"]')
            self.page.wait_for_url(f"**{self._base_url}**", timeout=20_000)
            logger.info("Indeed login successful")
            return True
        except Exception as exc:
            logger.warning(f"Indeed login skipped: {exc}")
            return True   # Continue even if login fails

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
            f"{self._base_url}/jobs"
            f"?q={quote_plus(keywords)}"
            f"&l={quote_plus(location)}"
            f"&iafilter=1"   # Easily Apply filter
        )
        try:
            self.page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 4)
            cards = self.page.query_selector_all('[data-jk], .job_seen_beacon, .slider_container')
            logger.info(f"Indeed [{location}]: found {len(cards)} cards")
            for card in cards[:30]:
                job = self._parse_card(card)
                if job and self.matches_criteria(job.title):
                    jobs.append(job)
        except Exception as exc:
            logger.error(f"Indeed search error: {exc}")
        return jobs

    def _parse_card(self, card) -> JobListing | None:
        try:
            title_el = card.query_selector('[class*="jobTitle"] a, .jcs-JobTitle')
            company_el = card.query_selector('[data-testid="company-name"], .companyName')
            location_el = card.query_selector('[data-testid="text-location"], .companyLocation')
            if not title_el:
                return None
            href = title_el.get_attribute("href") or ""
            if href.startswith("/"):
                href = self._base_url + href
            return JobListing(
                title=title_el.inner_text().strip(),
                company=company_el.inner_text().strip() if company_el else "Unknown",
                location=location_el.inner_text().strip() if location_el else "",
                url=href.split("&")[0],
                platform="indeed",
                easy_apply=True,
            )
        except Exception:
            return None

    # ------------------------------------------------------------------ apply

    def apply_to_job(self, job: JobListing) -> bool:
        dry_run = self.settings.get("dry_run", True)
        try:
            self.page.goto(job.url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 3)

            apply_btn = self.page.query_selector(
                'button[id*="applyButton"], a[id*="applyButton"], '
                'button:has-text("Apply now"), a:has-text("Apply now")'
            )
            if not apply_btn:
                logger.warning(f"Indeed: No apply button for {job.title}")
                return False

            if dry_run:
                logger.info(f"[DRY RUN] Would apply to: {job.title} @ {job.company} (Indeed)")
                return True

            apply_btn.click()
            self.human_delay(2, 3)
            return self._complete_indeed_form(job)

        except Exception as exc:
            logger.error(f"Indeed apply error ({job.title}): {exc}")
            return False

    def _complete_indeed_form(self, job: JobListing) -> bool:
        max_steps = 8
        resume_uploaded = False

        for step in range(max_steps):
            self.human_delay(2, 3)

            # Resume upload
            if not resume_uploaded:
                file_inp = self.page.query_selector('input[type="file"]')
                if file_inp:
                    file_inp.set_input_files(self.profile.get("resume_path", "resume.pdf"))
                    resume_uploaded = True
                    self.human_delay(1, 2)

            # Text inputs
            for inp in self.page.query_selector_all('input[type="text"], input[type="tel"], input[type="email"]'):
                try:
                    label_el = inp.evaluate_handle(
                        'el => el.closest("label") || document.querySelector(`label[for="${el.id}"]`)'
                    )
                    label_text = label_el.inner_text() if label_el else ""
                    answer = self.fill_common_field(label_text)
                    if answer and not inp.input_value():
                        self.slow_type(inp, answer)
                except Exception:
                    pass

            # Continue / Next
            next_btn = self.page.query_selector(
                'button:has-text("Continue"), button:has-text("Next"), '
                'button[data-tn-element="continueButton"]'
            )
            submit_btn = self.page.query_selector(
                'button:has-text("Submit your application"), '
                'button[data-tn-element="submitButton"]'
            )

            if submit_btn:
                submit_btn.click()
                self.human_delay(2, 3)
                logger.success(f"Applied to: {job.title} @ {job.company} (Indeed)")
                return True
            elif next_btn:
                next_btn.click()
            else:
                logger.warning(f"Indeed: Stuck at step {step} for {job.title}")
                break

        return False
