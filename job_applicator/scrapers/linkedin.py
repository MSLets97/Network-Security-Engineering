import time
from typing import List
from urllib.parse import quote_plus

from loguru import logger
from playwright.sync_api import Page, TimeoutError as PWTimeout

from .base import BaseScraper, JobListing


class LinkedInScraper(BaseScraper):
    BASE = "https://www.linkedin.com"

    @property
    def platform_name(self) -> str:
        return "linkedin"

    # ------------------------------------------------------------------ login

    def login(self) -> bool:
        try:
            self.page.goto(f"{self.BASE}/login", wait_until="domcontentloaded")
            self.human_delay(2, 4)
            self.page.fill("#username", self.platform_cfg["email"])
            self.human_delay(0.5, 1)
            self.page.fill("#password", self.platform_cfg["password"])
            self.human_delay(0.5, 1)
            self.page.click('button[type="submit"]')
            self.page.wait_for_url("**/feed**", timeout=20_000)
            logger.info("LinkedIn login successful")
            return True
        except Exception as exc:
            logger.error(f"LinkedIn login failed: {exc}")
            return False

    # ------------------------------------------------------------------ search

    def search_jobs(self) -> List[JobListing]:
        jobs: List[JobListing] = []
        keywords = " ".join(self.search_cfg.get("keywords", []))
        locations = self.search_cfg.get("locations", ["South Africa"])

        for location in locations:
            jobs.extend(self._search_location(keywords, location))
            if len(jobs) >= self.settings.get("max_applications_per_run", 15):
                break

        return jobs

    def _search_location(self, keywords: str, location: str) -> List[JobListing]:
        jobs: List[JobListing] = []
        url = (
            f"{self.BASE}/jobs/search/"
            f"?keywords={quote_plus(keywords)}"
            f"&location={quote_plus(location)}"
            f"&f_LF=f_AL"   # Easy Apply filter
        )
        try:
            self.page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(3, 5)
            self._scroll_to_load()
            cards = self.page.query_selector_all(".job-search-card, .jobs-search__results-list li")
            logger.info(f"LinkedIn [{location}]: found {len(cards)} cards")
            for card in cards[:30]:
                job = self._parse_card(card)
                if job and self.matches_criteria(job.title):
                    jobs.append(job)
        except Exception as exc:
            logger.error(f"LinkedIn search error ({location}): {exc}")
        return jobs

    def _parse_card(self, card) -> JobListing | None:
        try:
            title_el = card.query_selector(".base-search-card__title, .job-card-list__title")
            company_el = card.query_selector(".base-search-card__subtitle, .job-card-container__company-name")
            location_el = card.query_selector(".job-search-card__location, .job-card-container__metadata-item")
            link_el = card.query_selector("a.base-card__full-link, a.job-card-list__title")
            if not title_el or not link_el:
                return None
            return JobListing(
                title=title_el.inner_text().strip(),
                company=company_el.inner_text().strip() if company_el else "Unknown",
                location=location_el.inner_text().strip() if location_el else "",
                url=link_el.get_attribute("href").split("?")[0],
                platform="linkedin",
                easy_apply=True,
            )
        except Exception:
            return None

    def _scroll_to_load(self):
        for _ in range(3):
            self.page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            self.human_delay(1.5, 2.5)

    # ------------------------------------------------------------------ apply

    def apply_to_job(self, job: JobListing) -> bool:
        dry_run = self.settings.get("dry_run", True)
        try:
            self.page.goto(job.url, wait_until="domcontentloaded", timeout=30_000)
            self.human_delay(2, 4)

            # Click Easy Apply button
            apply_btn = self.page.query_selector(
                'button.jobs-apply-button, button[aria-label*="Easy Apply"]'
            )
            if not apply_btn:
                logger.warning(f"LinkedIn: No Easy Apply button for {job.title}")
                return False

            if dry_run:
                logger.info(f"[DRY RUN] Would apply to: {job.title} @ {job.company}")
                return True

            apply_btn.click()
            self.human_delay(2, 3)
            return self._complete_easy_apply_form(job)

        except Exception as exc:
            logger.error(f"LinkedIn apply error ({job.title}): {exc}")
            return False

    def _complete_easy_apply_form(self, job: JobListing) -> bool:
        """Step through the LinkedIn Easy Apply modal, filling fields and uploading resume."""
        modal_sel = 'div[data-test-modal], .jobs-easy-apply-modal'
        resume_uploaded = False
        max_steps = 10

        for step in range(max_steps):
            self.human_delay(1.5, 2.5)
            modal = self.page.query_selector(modal_sel)
            if not modal:
                break

            # Upload resume if file input present and not yet uploaded
            if not resume_uploaded:
                file_input = self.page.query_selector('input[type="file"]')
                if file_input:
                    resume_path = self.profile.get("resume_path", "resume.pdf")
                    file_input.set_input_files(resume_path)
                    resume_uploaded = True
                    self.human_delay(1, 2)

            # Fill text inputs
            for inp in self.page.query_selector_all('input[type="text"], input[type="tel"], input[type="email"]'):
                try:
                    label_el = self.page.query_selector(f'label[for="{inp.get_attribute("id")}"]')
                    label_text = label_el.inner_text() if label_el else inp.get_attribute("placeholder") or ""
                    answer = self.fill_common_field(label_text)
                    if answer and not inp.input_value():
                        self.slow_type(inp, answer)
                except Exception:
                    pass

            # Fill number inputs
            for inp in self.page.query_selector_all('input[type="number"]'):
                try:
                    if not inp.input_value():
                        label_el = self.page.query_selector(f'label[for="{inp.get_attribute("id")}"]')
                        label_text = label_el.inner_text() if label_el else ""
                        answer = self.fill_common_field(label_text)
                        if answer:
                            inp.fill(answer)
                except Exception:
                    pass

            # Handle select dropdowns
            for sel_el in self.page.query_selector_all("select"):
                try:
                    if not sel_el.input_value():
                        options = sel_el.query_selector_all("option")
                        if options:
                            # Pick first non-placeholder option
                            for opt in options:
                                val = opt.get_attribute("value")
                                if val and val not in ("", "0"):
                                    sel_el.select_option(value=val)
                                    break
                except Exception:
                    pass

            # Determine next action
            submit_btn = self.page.query_selector('button[aria-label*="Submit"], button[aria-label*="submit"]')
            next_btn = self.page.query_selector('button[aria-label*="Continue"], button[aria-label*="Next"]')
            review_btn = self.page.query_selector('button[aria-label*="Review"]')

            if submit_btn:
                submit_btn.click()
                self.human_delay(2, 3)
                logger.success(f"Applied to: {job.title} @ {job.company} (LinkedIn)")
                # Dismiss confirmation
                try:
                    self.page.click('button[aria-label*="Dismiss"], button[aria-label*="Close"]', timeout=3000)
                except Exception:
                    pass
                return True
            elif review_btn:
                review_btn.click()
            elif next_btn:
                next_btn.click()
            else:
                logger.warning(f"LinkedIn: Could not find navigation button at step {step}")
                break

        logger.warning(f"LinkedIn: Did not complete application for {job.title}")
        return False
