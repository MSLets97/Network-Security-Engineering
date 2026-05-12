"""
J.A.R.V.I.S. CLI — Terminal Interface
Rich, colored terminal experience
"""

import sys
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme
from rich.live import Live
from rich.spinner import Spinner
from rich import box

from .core import JarvisSession

JARVIS_THEME = Theme(
    {
        "jarvis.primary": "bold cyan",
        "jarvis.secondary": "bold blue",
        "jarvis.accent": "bold gold1",
        "jarvis.user": "bold white",
        "jarvis.system": "dim cyan",
        "jarvis.error": "bold red",
        "jarvis.success": "bold green",
    }
)

BANNER = """
[bold cyan]
     ██╗ █████╗ ██████╗ ██╗   ██╗██╗███████╗
     ██║██╔══██╗██╔══██╗██║   ██║██║██╔════╝
     ██║███████║██████╔╝██║   ██║██║███████╗
██   ██║██╔══██║██╔══██╗╚██╗ ██╔╝██║╚════██║
╚█████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║███████║
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝
[/bold cyan]
[bold blue]  Just A Rather Very Intelligent System  v1.0[/bold blue]
[dim cyan]  Powered by Claude claude-opus-4-7 · All Systems Nominal[/dim cyan]
"""

HELP_TEXT = """
[bold cyan]JARVIS COMMANDS[/bold cyan]

  [bold white]help[/bold white]     — Show this help
  [bold white]clear[/bold white]    — Clear conversation history
  [bold white]exit[/bold white]     — Shut down JARVIS
  [bold white]quit[/bold white]     — Shut down JARVIS

[dim]Press Ctrl+C to interrupt at any time[/dim]
"""


console = Console(theme=JARVIS_THEME)


def print_banner():
    console.print(BANNER)
    console.print(
        Panel(
            "[dim cyan]Online and ready, sir. What shall we work on today?[/dim cyan]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )
    console.print()


def print_help():
    console.print(Panel(HELP_TEXT, title="[bold cyan]Help[/bold cyan]", border_style="blue"))


def run_cli(voice_enabled: bool = False):
    """Run the JARVIS CLI interface."""
    from .voice import VoiceModule

    print_banner()

    session = JarvisSession()
    voice = None

    if voice_enabled:
        try:
            voice = VoiceModule()
            console.print(
                "[jarvis.system]Voice module online. Speak after the prompt.[/jarvis.system]\n"
            )
        except Exception as e:
            console.print(f"[jarvis.error]Voice module offline: {e}[/jarvis.error]\n")

    while True:
        try:
            if voice and voice_enabled:
                console.print("[bold cyan]🎤 Listening...[/bold cyan]", end=" ")
                user_input = voice.listen()
                if not user_input:
                    console.print("[dim]Nothing heard. Try again or type your query.[/dim]")
                    user_input = console.input("[bold cyan]YOU ▶[/bold cyan] ")
                else:
                    console.print(f"[bold white]{user_input}[/bold white]")
            else:
                user_input = console.input("[bold cyan]YOU ▶[/bold cyan] ")

            if not user_input.strip():
                continue

            cmd = user_input.strip().lower()
            if cmd in ("exit", "quit"):
                console.print(
                    "\n[jarvis.secondary]Shutting down all systems. Goodbye, sir.[/jarvis.secondary]\n"
                )
                break
            elif cmd == "clear":
                session.reset()
                console.print("[jarvis.system]Conversation history cleared.[/jarvis.system]\n")
                continue
            elif cmd == "help":
                print_help()
                continue

            console.print()
            console.print("[bold cyan]JARVIS ▶[/bold cyan]", end=" ")

            response_buffer = []

            with Live(
                Text("", style="white"),
                console=console,
                refresh_per_second=20,
                transient=False,
            ) as live:
                def on_chunk(chunk: str):
                    response_buffer.append(chunk)
                    live.update(Text("".join(response_buffer), style="white"))

                session.chat(user_input, on_chunk=on_chunk)

            full_response = "".join(response_buffer)
            console.print()

            if voice and voice_enabled:
                try:
                    voice.speak(full_response[:500])
                except Exception:
                    pass

            console.print()

        except KeyboardInterrupt:
            console.print(
                "\n\n[jarvis.secondary]Interrupted. Standing by.[/jarvis.secondary]\n"
            )
            continue
        except EOFError:
            console.print(
                "\n[jarvis.secondary]Shutting down all systems. Goodbye, sir.[/jarvis.secondary]\n"
            )
            break
        except Exception as e:
            console.print(f"\n[jarvis.error]System error: {e}[/jarvis.error]\n")
