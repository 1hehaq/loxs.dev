from core.utils import *

def display_menu():
    title = r"""
 ____           ____  ___                
|    |    _____ \   \/  /  ______
|    |   /     \ \     /  /  ___/
|    |__(   O  / /     \  \___  \
|_______/\____/ /___/\  \ /_____/ 
                      \_/                 
"""
    print(Fore.RED + Style.BRIGHT + title.center(72))
    print(Fore.WHITE + Style.BRIGHT + "─" * 72)
    border_color = Fore.CYAN + Style.BRIGHT
    option_color = Fore.WHITE + Style.BRIGHT  

    print(border_color + "┌" + "─" * 72 + "┐")
    options = [
        "1] LFi Scanner",
        "2] OR Scanner",
        "3] SQLi Scanner",
        "4] XSS Scanner",
        "5] CRLF Scanner",
        "6] tool Update",
        "7] Exit"
    ]
    for option in options:
        print(border_color + "│" + option_color + option.ljust(72) + border_color + "│")
    print(border_color + "└" + "─" * 72 + "┘")
    authors = "Created by: Coffinxp, 1hehaq, HexSh1dow, Naho, AnonKryptiQuz, Hghost010"
    instructions = "Select an option by entering the corresponding number:"
    print(Fore.WHITE + Style.BRIGHT + "─" * 72)
    print(Fore.WHITE + Style.BRIGHT + authors.center(72))
    print(Fore.WHITE + Style.BRIGHT + "─" * 72)
    print(Fore.WHITE + Style.BRIGHT + instructions.center(72))
    print(Fore.WHITE + Style.BRIGHT + "─" * 72)

def print_exit_menu():
    clear_screen()
    panel = Panel(r"""
 ______               ______              
|   __ \.--.--.-----.|   __ \.--.--.-----.
|   __ <|  |  |  -__||   __ <|  |  |  -__|
|______/|___  |_____||______/|___  |_____|
        |_____|              |_____|      
    
Credit: Coffinxp - 1hehaq - HexSh1dow - AnonKryptiQuz - Naho - Hghost010
        """,
        style="bold green",
        border_style="blue",
        expand=False
    )
    rich_print(panel)
    print(Color.RED + "\n\nSession Off..\n")
    sys.exit()

def main():
    display_menu()

if __name__ == "__main__":
    main()