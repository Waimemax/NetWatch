
import argparse

from rich.console import Console
from rich.panel import Panel

from netwatch import __version__

console = Console()


def create_parser():
    """Create and configure the NetWatch argument parser."""

    parser = argparse.ArgumentParser(
        prog="netwatch",
        description="NetWatch - Network Discovery and Monitoring Tool",
        epilog="Use NetWatch only on networks you own or have permission to assess.",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def main():
    """Run the NetWatch command-line interface."""

    parser = create_parser()
    parser.parse_args()

    console.print(
        Panel(
            "[bold green]NetWatch[/bold green]\n"
            "[cyan]Network Discovery and Monitoring Tool[/cyan]\n"
            f"[dim]Version {__version__}[/dim]",
            title="[bold white]Welcome[/bold white]",
            border_style="green",
        )
    )

    console.print(
        "[yellow]No command selected yet. "
        "Use --help to see available options.[/yellow]"
    )


if __name__ == "__main__":
    main()
