#!/usr/bin/env python3
"""Preview the app UI with simulated job data — no browser or credentials needed."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box

console = Console()

MOCK_JOBS = [
    ("Network Security Engineer",    "Vodacom",           "Johannesburg, SA",  "linkedin",      "applied"),
    ("Cybersecurity Analyst",        "Standard Bank",     "Cape Town, SA",     "linkedin",      "applied"),
    ("Security Operations (SOC)",    "Nedbank",           "Remote",            "indeed",        "applied"),
    ("IT Security Specialist",       "MTN SA",            "Johannesburg, SA",  "pnet",          "applied"),
    ("Senior SecOps Engineer",       "Absa Group",        "Hybrid - SA",       "glassdoor",     "failed"),
    ("Cloud Security Engineer",      "Accenture SA",      "Remote",            "weworkremotely","applied"),
    ("InfoSec Analyst",              "PwC South Africa",  "Cape Town, SA",     "remoteco",      "applied"),
    ("Security Architect",           "SA Government",     "Pretoria, SA",      "govza_dpsa",    "found"),
    ("Cyber Risk Analyst",           "Deloitte SA",       "Johannesburg, SA",  "indeed",        "applied"),
    ("Network Engineer (Security)",  "Liquid Telecom",    "Remote",            "pnet",          "skipped"),
]

PLATFORM_COLORS = {
    "linkedin":      "blue",
    "indeed":        "red",
    "glassdoor":     "green",
    "weworkremotely":"magenta",
    "remoteco":      "cyan",
    "pnet":          "yellow",
    "govza_dpsa":    "white",
}

STATUS_COLORS = {
    "applied":  "bold green",
    "found":    "bold cyan",
    "failed":   "bold red",
    "skipped":  "dim white",
}


def banner():
    console.print()
    console.print(Panel.fit(
        "[bold white]  Job Applicator  [/bold white]\n"
        "[dim]Searches LinkedIn · Indeed · Glassdoor · PNet · Remote.co · We Work Remotely · SA Government[/dim]",
        border_style="bright_blue",
    ))
    console.print()


def show_config():
    console.print("[bold]Configuration loaded:[/bold]")
    console.print("  Profile   : [cyan]Your Name[/cyan] | your.email@example.com | +27 XX XXX XXXX")
    console.print("  Keywords  : [yellow]Network Security Engineer · Cybersecurity Analyst · Security Operations[/yellow]")
    console.print("  Locations : Cape Town · Johannesburg · South Africa · Remote")
    console.print("  Resume    : [green]resume.pdf[/green]  ✓ found")
    console.print("  Mode      : [bold yellow]DRY RUN[/bold yellow] (pass --apply to submit for real)")
    console.print()


def simulate_platform(name: str, jobs_found: list):
    console.rule(f"[bold blue]{name.upper()}")
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=console, transient=True) as p:
        t = p.add_task(f"Logging in to {name}...", total=None)
        time.sleep(0.6)
        p.update(t, description=f"Searching jobs on {name}...")
        time.sleep(0.8)
        p.update(t, description=f"Found {len(jobs_found)} matching jobs")
        time.sleep(0.4)

    console.print(f"  [green]✓[/green] Login OK  |  [cyan]{len(jobs_found)} jobs matched your criteria[/cyan]")
    for title, company, location, platform, status in jobs_found:
        color = PLATFORM_COLORS.get(platform, "white")
        s_color = STATUS_COLORS.get(status, "white")
        if status == "applied":
            icon = "[green]✓[/green]"
        elif status == "failed":
            icon = "[red]✗[/red]"
        elif status == "skipped":
            icon = "[dim]—[/dim]"
        else:
            icon = "[cyan]~[/cyan]"
        console.print(f"    {icon} [{color}]{title}[/{color}] @ [bold]{company}[/bold]  [dim]{location}[/dim]  [{s_color}][{status}][/{s_color}]")
        time.sleep(0.15)
    console.print()


def show_stats():
    console.rule("[bold green]Run Complete")

    stats_table = Table(title="Application Stats", box=box.ROUNDED)
    stats_table.add_column("Status",  style="cyan")
    stats_table.add_column("Count",   justify="right", style="bold")
    status_counts = {}
    for *_, status in MOCK_JOBS:
        status_counts[status] = status_counts.get(status, 0) + 1
    for status, count in sorted(status_counts.items()):
        stats_table.add_row(status, str(count))
    console.print(stats_table)
    console.print()

    jobs_table = Table(title="Jobs Found This Run", box=box.SIMPLE_HEAVY)
    jobs_table.add_column("Title",    style="cyan", max_width=38)
    jobs_table.add_column("Company",  style="white")
    jobs_table.add_column("Platform", style="yellow")
    jobs_table.add_column("Location", style="dim")
    jobs_table.add_column("Status",   justify="center")
    for title, company, location, platform, status in MOCK_JOBS:
        s_color = STATUS_COLORS.get(status, "white")
        jobs_table.add_row(title, company, platform, location, f"[{s_color}]{status}[/{s_color}]")
    console.print(jobs_table)
    console.print()

    console.print(Panel(
        f"[bold green]7 applications submitted[/bold green]  |  "
        f"[red]1 failed[/red]  |  "
        f"[dim]1 skipped (excluded keyword)[/dim]  |  "
        f"[cyan]1 found (gov — manual Z83 required)[/cyan]\n\n"
        f"[dim]Full log saved to:  output/applicator.log[/dim]",
        title="Summary",
        border_style="green",
    ))


def main():
    banner()
    show_config()

    by_platform = {}
    for job in MOCK_JOBS:
        p = job[3]
        by_platform.setdefault(p, []).append(job)

    platform_groups = [
        ("LinkedIn",           by_platform.get("linkedin", [])),
        ("Indeed",             by_platform.get("indeed", [])),
        ("Glassdoor",          by_platform.get("glassdoor", [])),
        ("PNet",               by_platform.get("pnet", [])),
        ("We Work Remotely",   by_platform.get("weworkremotely", [])),
        ("Remote.co",          by_platform.get("remoteco", [])),
        ("SA Government",      by_platform.get("govza_dpsa", [])),
    ]

    for name, jobs in platform_groups:
        if jobs:
            simulate_platform(name, jobs)

    show_stats()


if __name__ == "__main__":
    main()
