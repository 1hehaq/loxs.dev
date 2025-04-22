from core.utils import *

def run_xss_scanner(scan_state=None):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.getLogger('WDM').setLevel(logging.ERROR)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    console = Console()

    driver_pool = Queue()
    driver_lock = Lock()

    def load_payloads(payload_file):
        try:
            with open(payload_file, "r") as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(Fore.RED + f"[!] Error loading payloads: {e}")
            exit()

    def generate_payload_urls(url, payload):
        url_combinations = []
        scheme, netloc, path, query_string, fragment = urlsplit(url)
        if not scheme:
            scheme = 'http'
        query_params = parse_qs(query_string, keep_blank_values=True)
        for key in query_params.keys():
            modified_params = query_params.copy()
            modified_params[key] = [payload]
            modified_query_string = urlencode(modified_params, doseq=True)
            modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
            url_combinations.append(modified_url)
        return url_combinations

    def create_driver():
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-browser-side-navigation")
        chrome_options.add_argument("--disable-infobars")
        chrome_options.add_argument("--disable-notifications")
        chrome_options.page_load_strategy = 'eager'
        logging.disable(logging.CRITICAL)
        
        driver_service = Service(ChromeDriverManager().install())
        return webdriver.Chrome(service=driver_service, options=chrome_options)

    def get_driver():
        try:
            return driver_pool.get_nowait()
        except:
            with driver_lock:
                return create_driver()

    def return_driver(driver):
        driver_pool.put(driver)

    def check_vulnerability(url, payload, vulnerable_urls, total_scanned, timeout, scan_state):
        driver = get_driver()
        try:
            payload_urls = generate_payload_urls(url, payload)
            if not payload_urls:
                return

            for payload_url in payload_urls:
                try:
                    driver.get(payload_url)
                    
                    total_scanned[0] += 1
                    
                    try:
                        alert = WebDriverWait(driver, timeout).until(EC.alert_is_present())
                        alert_text = alert.text

                        if alert_text:
                            result = Fore.GREEN + f"[✓]{Fore.CYAN} Vulnerable:{Fore.GREEN} {payload_url} {Fore.CYAN} - Alert Text: {alert_text}"
                            print(result)
                            vulnerable_urls.append(payload_url)
                            if scan_state:
                                scan_state['vulnerability_found'] = True
                                scan_state['vulnerable_urls'].append(payload_url)
                                scan_state['total_found'] += 1
                            alert.accept()
                        else:
                            result = Fore.RED + f"[✗]{Fore.CYAN} Not Vulnerable:{Fore.RED} {payload_url}"
                            print(result)

                    except TimeoutException:
                        print(Fore.RED + f"[✗]{Fore.CYAN} Not Vulnerable:{Fore.RED} {payload_url}")

                except UnexpectedAlertPresentException:
                    pass
        finally:
            return_driver(driver)



    def run_scan(urls, payload_file, timeout, scan_state):
        payloads = load_payloads(payload_file)
        vulnerable_urls = []
        total_scanned = [0]
        
        for _ in range(3):
            driver_pool.put(create_driver())
        
        try:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = []
                for url in urls:
                    for payload in payloads:
                        futures.append(
                            executor.submit(
                                check_vulnerability,
                                url,
                                payload,
                                vulnerable_urls,
                                total_scanned,
                                timeout,
                                scan_state
                            )
                        )
                
                for future in as_completed(futures):
                    try:
                        future.result(timeout)
                    except Exception as e:
                        print(Fore.RED + f"[!] Error during scan: {e}")
                        
        finally:
            while not driver_pool.empty():
                driver = driver_pool.get()
                driver.quit()
                
            return vulnerable_urls, total_scanned[0]

    def print_scan_summary(total_found, total_scanned, start_time):
        summary = [
            "→ Scanning finished.",
            f"• Total found: {Fore.GREEN}{total_found}{Fore.YELLOW}",
            f"• Total scanned: {total_scanned}",
            f"• Time taken: {int(time.time() - start_time)} seconds"
        ]
        for line in summary:
            print(Fore.YELLOW + line)

    def save_results(vulnerable_urls, total_found, total_scanned, start_time):
        action = input(Fore.CYAN + "[?] Do you want to generate an HTML report? (y/n): ").strip().lower()
        if action == 'y':
            html_content = generate_html_report("Cross-Site Scripting (XSS)", total_found, total_scanned, int(time.time() - start_time), vulnerable_urls)
            
            filename = input(Fore.CYAN + "[?] Enter the filename for the HTML report or press Enter to use 'xssreport.html': ").strip()
            if not filename:
                filename = 'xssreport.html'
                print(Fore.YELLOW + "[i] No filename provided. Using 'xssreport.html'.")

            print(f"DEBUG: Chosen filename: '{filename}'")
            
            report_file = save_html_report(html_content, filename)
        else:
            print(Fore.RED + "\nExiting...")
            exit()

    def get_file_path(prompt_text):
        completer = PathCompleter()
        return prompt(prompt_text, completer=completer).strip()

    def prompt_for_urls():
        while True:
            try:
                url_input = get_file_path("[?] Enter the path to the input file containing URLs (or press Enter to enter a single URL): ")
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
                        print(Fore.GREEN + "Welcome to the XSS Scanner!\n")
            except Exception as e:
                print(Fore.RED + f"[!] Error reading the input file. Exception: {str(e)}")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the XSS Scanner!\n")


    def prompt_for_valid_file_path(prompt_text):
        while True:
            file_path = get_file_path(prompt_text).strip()
            if not file_path:
                print(Fore.RED + "[!] You must provide a file containing the payloads.")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the XSS Scanner!\n")
                continue
            if os.path.isfile(file_path):
                return file_path
            else:
                print(Fore.RED + "[!] Error reading the input file.")
                input(Fore.YELLOW + "[i] Press Enter to try again...")
                clear_screen()
                print(Fore.GREEN + "Welcome to the XSS Scanner!\n")

    def main():
        clear_screen()
        panel = Panel(r"""
     _  __________  ____________   _  ___  __________
    | |/_/ __/ __/ / __/ ___/ _ | / |/ / |/ / __/ _  |
    >  <_\ \_\ \  _\ \/ /__/ __ |/    /    / _// , _/
  /_/|_/___/___/ /___/\___/_/ |_/_/|_/_/|_/___/_/|_|  
                """,
                    style="bold green",
                    border_style="blue",
                    expand=False
                )

        console.print(panel, "\n")
        print(Fore.GREEN + "Welcome to the XSS Testing Tool!\n")
        urls = prompt_for_urls()

        payload_file = prompt_for_valid_file_path("[?] Enter the path to the payloads file: ")
        
        try:
            timeout = float(input(Fore.CYAN + "Enter the timeout duration for each request (Press Enter for 0.5): "))
        except ValueError:
            timeout = 0.5

        clear_screen()
        print(f"{Fore.CYAN}[i] Starting scan...\n")

        scan_state = {'vulnerability_found': False, 'total_found': 0, 'vulnerable_urls': []}
        all_vulnerable_urls = []
        total_scanned = 0
        start_time = time.time()

        try:
            for url in urls:
                box_content = f" → Scanning URL: {url} "
                box_width = max(len(box_content) + 2, 40)
                print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
                print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
                print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n")

                vulnerable_urls, scanned = run_scan([url], payload_file, timeout, scan_state)
                all_vulnerable_urls.extend(vulnerable_urls)
                total_scanned += scanned

        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted by the user.")
            print_scan_summary(scan_state['total_found'], total_scanned, start_time)
            save_results(scan_state['vulnerable_urls'], scan_state['total_found'], total_scanned, start_time)
            exit()

        print_scan_summary(scan_state['total_found'], total_scanned, start_time)
        save_results(scan_state['vulnerable_urls'], scan_state['total_found'], total_scanned, start_time)
        exit()


    if __name__ == "__main__":
        try:
            main()
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted by the user. Exiting...")
            sys.exit()