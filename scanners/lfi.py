from core.utils import *

def run_lfi_scanner(scan_state=None):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    init(autoreset=True)

    def get_random_user_agent():
        return random.choice(USER_AGENTS)
    
    def check_and_install_packages(packages):
        for package, version in packages.items():
            try:
                __import__(package)
            except ImportError:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', f"{package}=={version}"])

    def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
        session = requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
    
    def test_lfi(url, payloads, success_criteria, max_threads=5):
        def check_payload(payload):
            encoded_payload = urllib.parse.quote(payload.strip())
            target_url = f"{url}{encoded_payload}"
            start_time = time.time()
            try:
                response = requests.get(target_url)
                response_time = round(time.time() - start_time, 2)
                result = None
                is_vulnerable = False
                if response.status_code == 200:
                    is_vulnerable = any(re.search(pattern, response.text) for pattern in success_criteria)
                    if is_vulnerable:
                        result = Fore.GREEN + f"[✓]{Fore.CYAN} Vulnerable: {Fore.GREEN} {target_url} {Fore.CYAN} - Response Time: {response_time} seconds"
                    else:
                        result = Fore.RED + f"[✗]{Fore.CYAN} Not Vulnerable: {Fore.RED} {target_url} {Fore.CYAN} - Response Time: {response_time} seconds"
                else:
                    result = Fore.RED + f"[✗]{Fore.CYAN} Not Vulnerable: {Fore.RED} {target_url} {Fore.CYAN} - Response Time: {response_time} seconds"
                if is_vulnerable and scan_state:
                    scan_state['vulnerability_found'] = True
                    scan_state['vulnerable_urls'].append(target_url)
                    scan_state['total_found'] += 1
                if scan_state:
                    scan_state['total_scanned'] += 1
                return result, is_vulnerable
            except requests.exceptions.RequestException as e:
                print(Fore.RED + f"[!] Error accessing {target_url}: {str(e)}")
                return None, False
        found_vulnerabilities = 0
        vulnerable_urls = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_payload = {executor.submit(check_payload, payload): payload for payload in payloads}
            for future in as_completed(future_to_payload):
                payload = future_to_payload[future]
                try:
                    result, is_vulnerable = future.result()
                    if result:
                        print(Fore.YELLOW + f"[→] Scanning with payload: {payload.strip()}")
                        print(result)
                        if is_vulnerable:
                            found_vulnerabilities += 1
                            vulnerable_urls.append(url + urllib.parse.quote(payload.strip()))
                except Exception as e:
                    print(Fore.RED + f"[!] Exception occurred for payload {payload}: {str(e)}")
        return found_vulnerabilities, vulnerable_urls

    def save_results(vulnerable_urls, total_found, total_scanned, start_time):
        generate_report = input(f"{Fore.CYAN}\n[?] Do you want to generate an HTML report? (y/n): ").strip().lower()
        if generate_report == 'y':
            html_content = generate_html_report("Local File Inclusion (LFI)", total_found, total_scanned, int(time.time() - start_time), vulnerable_urls)
            filename = input(f"{Fore.CYAN}[?] Enter the filename for the HTML report: ").strip()
            report_file = save_html_report(html_content, filename)
            
    def prompt_for_urls():
        while True:
            try:
                url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
                if url_input:
                    if not os.path.isfile(url_input):
                        raise FileNotFoundError(f"File not found: {url_input}")
                    with open(url_input) as file:
                        urls = [line.strip() for line in file if line.strip()]
                    return urls
                else:
                    single_url = input(Fore.CYAN + "[?] Enter a single URL to scan: ").strip()
                    if single_url:
                        return [single_url]
                    else:
                        print(Fore.RED + "[!] You must provide either a file with URLs or a single URL.")
                        input(Fore.YELLOW + "\n[i] Press Enter to try again...")
                        clear_screen()
                        print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")
            except Exception as e:
                print(Fore.RED + f"[!] Error reading input file: {url_input}. Exception: {str(e)}")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the LFI Testing Tool! - AnonKryptiQuz x 1hehaq x Coffinxp x Hexsh1dow x Naho x Hghost010\n")

    def prompt_for_payloads():
        while True:
            try:
                payload_input = get_file_path("[?] Enter the path to the payloads file: ")
                if not os.path.isfile(payload_input):
                    raise FileNotFoundError(f"File not found: {payload_input}")
                with open(payload_input, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                return payloads
            except Exception as e:
                print(Fore.RED + f"[!] Error reading payload file: {payload_input}. Exception: {str(e)}")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")
                
    def print_scan_summary(total_found, total_scanned, start_time):
        summary = [
            "→ Scanning finished.",
            f"• Total found: {Fore.GREEN}{total_found}{Fore.YELLOW}",
            f"• Total scanned: {total_scanned}",
            f"• Time taken: {int(time.time() - start_time)} seconds"
        ]
        max_length = max(len(line.replace(Fore.GREEN, '').replace(Fore.YELLOW, '')) for line in summary)
        border = "┌" + "─" * (max_length + 2) + "┐"
        bottom_border = "└" + "─" * (max_length + 2) + "┘"
        print(Fore.YELLOW + f"\n{border}")
        for line in summary:
            padded_line = line.replace(Fore.GREEN, '').replace(Fore.YELLOW, '')
            padding = max_length - len(padded_line)
            print(Fore.YELLOW + f"│ {line}{' ' * padding} │{Fore.YELLOW}")
        print(Fore.YELLOW + bottom_border)

    def get_file_path(prompt_text):
        completer = PathCompleter()
        return prompt(prompt_text, completer=completer).strip()

    clear_screen()
    required_packages = {
        'requests': '2.28.1',
        'prompt_toolkit': '3.0.36',
        'colorama': '0.4.6'
    }
    check_and_install_packages(required_packages)
    clear_screen()
    panel = Panel(
    r"""
    __    __________   _____                                 
   / /   / ____/  _/  / ___/_________ _____  ____  ___  _____
  / /   / /_   / /    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / /___/ __/ _/ /    ___/ / /__/ /_/ / / / / / / /  __/ /    
/_____/_/   /___/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     

            """,
    style="bold green",
    border_style="blue",
    expand=False
    )
    rich_print(panel, "\n")
    print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")
    urls = prompt_for_urls()
    payloads = prompt_for_payloads()
    success_criteria_input = input("[?] Enter the success criteria patterns (comma-separated, e.g: 'root:,admin:', press Enter for 'root:x:0:'): ").strip()
    success_criteria = [pattern.strip() for pattern in success_criteria_input.split(',')] if success_criteria_input else ['root:x:0:']
    max_threads_input = input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip()
    max_threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 10 else 5
    print(Fore.YELLOW + "\n[i] Loading, Please Wait...")
    clear_screen()
    print(Fore.CYAN + "[i] Starting scan...\n")
    for url in urls:
        get_random_user_agent()
    total_found = 0
    total_scanned = 0
    start_time = time.time()
    vulnerable_urls = []
    if scan_state is None:
        scan_state = {
            'vulnerability_found': False,
            'vulnerable_urls': [],
            'total_found': 0,
            'total_scanned': 0
        }
    if payloads:
        for url in urls:
            box_content = f" → Scanning URL: {url} "
            box_width = max(len(box_content) + 2, 40)
            print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
            print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
            print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n")
            found, urls_with_payloads = test_lfi(url, payloads, success_criteria, max_threads)
            total_found += found
            total_scanned += len(payloads)
            vulnerable_urls.extend(urls_with_payloads)
    print_scan_summary(total_found, total_scanned, start_time)
    save_results(vulnerable_urls, total_found, total_scanned, start_time)
    if scan_state['vulnerability_found']:
        print(Fore.GREEN + f"\n[+] Vulnerabilities found: {scan_state['total_found']}")
        print(Fore.GREEN + f"[+] Vulnerable URLs:")
        for url in scan_state['vulnerable_urls']:
            print(Fore.GREEN + f"    {url}")
    else:
        print(Fore.YELLOW + "\n[-] No vulnerabilities found.")
    print(Fore.CYAN + f"\n[i] Total URLs scanned: {scan_state['total_scanned']}")
    exit()
