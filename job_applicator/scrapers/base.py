import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional

from playwright.sync_api import Page


@dataclass
class JobListing:
    title: str
    company: str
    url: str
    platform: str
    location: str = ""
    salary: str = ""
    job_type: str = ""
    description: str = ""
    easy_apply: bool = False


class BaseScraper(ABC):
    def __init__(self, config: dict, page: Page):
        self.config = config
        self.page = page
        self.profile = config["profile"]
        self.search_cfg = config["search"]
        self.settings = config["settings"]
        self.platform_cfg = config["platforms"].get(self.platform_name, {})

    @property
    @abstractmethod
    def platform_name(self) -> str:
        pass

    @abstractmethod
    def login(self) -> bool:
        """Return True if login succeeded."""
        pass

    @abstractmethod
    def search_jobs(self) -> List[JobListing]:
        """Return list of job listings matching search criteria."""
        pass

    @abstractmethod
    def apply_to_job(self, job: JobListing) -> bool:
        """Submit application; return True on success."""
        pass

    # ------------------------------------------------------------------ helpers

    def human_delay(self, min_s: float = 1.5, max_s: float = 4.0):
        time.sleep(random.uniform(min_s, max_s))

    def slow_type(self, locator, text: str):
        """Type text character-by-character to mimic human input."""
        locator.click()
        for char in text:
            locator.type(char)
            time.sleep(random.uniform(0.03, 0.12))

    def matches_criteria(self, title: str, description: str = "") -> bool:
        title_l = title.lower()
        desc_l = description.lower()
        for kw in self.search_cfg.get("exclude_keywords", []):
            if kw.lower() in title_l:
                return False
        for kw in self.search_cfg.get("keywords", []):
            if kw.lower() in title_l or kw.lower() in desc_l:
                return True
        return False

    def fill_common_field(self, label_text: str) -> Optional[str]:
        """Return a canned answer for common application form fields."""
        label = label_text.lower()
        p = self.profile
        if "name" in label and "first" in label:
            return p["full_name"].split()[0]
        if "name" in label and "last" in label:
            return p["full_name"].split()[-1]
        if "full name" in label or ("name" in label and "company" not in label):
            return p["full_name"]
        if "email" in label:
            return p["email"]
        if "phone" in label or "mobile" in label or "contact" in label:
            return p["phone"]
        if "linkedin" in label:
            return p.get("linkedin_url", "")
        if "portfolio" in label or "website" in label:
            return p.get("portfolio_url", "")
        if "city" in label:
            return p.get("city", p["location"])
        if "location" in label or "address" in label:
            return p["location"]
        if "experience" in label and "year" in label:
            return p.get("years_of_experience", "3")
        if "education" in label or "degree" in label or "qualification" in label:
            return p.get("highest_education", "Bachelor's Degree")
        if "notice" in label:
            return p.get("notice_period", "1 month")
        if "relocat" in label:
            return p.get("willing_to_relocate", "No")
        if "authoriz" in label or "authoris" in label or "permit" in label:
            return p.get("work_authorization", "Yes")
        if "citizen" in label:
            return p.get("sa_citizen", "Yes")
        if "salary" in label or "remuneration" in label or "ctc" in label:
            return str(self.search_cfg.get("salary_min", "Negotiable"))
        return None
