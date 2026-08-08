from colorama import init as colorama_init, Fore, Style

colorama_init(autoreset=True)

BANNER = r"""
 █████╗ ██╗      ██████╗ ██╗   ██╗ ██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗██║      ██╔══██╗██║   ██║██╔════╝     ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║█████╗██████╔╝██║   ██║██║  ███╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║╚════╝██╔══██╗██║   ██║██║   ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║██║      ██████╔╝╚██████╔╝╚██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝╚═╝      ╚═════╝  ╚═════╝  ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                    one command at a time. one target. no mercy.
"""


def print_startup_banner(live: bool, target: str, guide: str, iterations: int) -> None:
    """Print the ASCII banner and a one-line status about LIVE/OFFLINE mode."""
    mode = (Fore.GREEN + 'LIVE') if live else (Fore.YELLOW + 'OFFLINE')
    print(Fore.CYAN + BANNER)
    status = f"Mode: {mode}{Style.RESET_ALL} | Target: {target or 'N/A'} | Guide: {guide or 'N/A'} | Iterations: {iterations}"
    print(status)
