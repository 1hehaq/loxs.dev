from core.utils import *

def run_or_scanner(scan_state=None):
    init()
    scan_active = True
    executor = None
    drivers = []            
    
    def get_chrome_driver():
        if not scan_active:
            return None
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-browser-side-navigation")
        chrome_options.add_argument("--disable-infobars")
        chrome_options.add_argument("--disable-notifications")
        chrome_options.page_load_strategy = 'eager'
        logging.disable(logging.CRITICAL)
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(15)
        drivers.append(driver)
        return driver

    def check_payload_with_selenium(url, payload, param_name=None):
        if not scan_active:
            return False
        driver = None
        try:
            driver = get_chrome_driver()
            if not driver:
                return False
            print(Fore.YELLOW + f"[→] Testing {param_name if param_name else 'path'}: {Fore.CYAN}{url}")
            driver.get(url)
            WebDriverWait(driver, 10).until(
                lambda d: d.execute_script('return document.readyState') == 'complete'
            )
            current_url = driver.current_url.lower()
            if "google.com" in current_url:
                if current_url.startswith("https://google.com") or "google.com" in current_url.split("/")[2]: 
                    if scan_state:
                        scan_state['vulnerability_found'] = True
                        scan_state['vulnerable_urls'].append(url)
                        scan_state['total_found'] += 1
                    print(Fore.GREEN + f"[✓] Vulnerable: {url}")
                    return True
                else:
                    print(Fore.RED + f"[✗] Not Vulnerable: {url}")
            else:
                print(Fore.RED + f"[✗] Not Vulnerable: {url}")
        except Exception as e:
            if scan_active:
                print(Fore.RED + f"[!] Error: {str(e)}")
            return False
        finally:
            if driver and driver in drivers:
                try:
                    driver.quit()
                    drivers.remove(driver)
                except:
                    pass
        return False

    def test_open_redirect(url, payloads, max_threads=5):
        nonlocal scan_active, executor
        found_vulnerabilities = 0
        vulnerable_urls = []
        parsed = urllib.parse.urlparse(url)
        print(Fore.MAGENTA + f"[i] Parsed URL: {parsed}")
        if not parsed.scheme:
            url = 'http://' + url
            parsed = urllib.parse.urlparse(url)
        try:
            if not parsed.query:
                print(Fore.YELLOW + "[i] No query parameters found. Testing path instead.")
                path = parsed.path
                executor = ThreadPoolExecutor(max_workers=max_threads)
                futures = []
                for payload in payloads:
                    if not scan_active:
                        break
                    payload = payload.strip()
                    if not payload:
                        continue
                    test_url = parsed._replace(path=path + payload)
                    futures.append(
                        executor.submit(
                            check_payload_with_selenium,
                            url=urllib.parse.urlunparse(test_url),
                            payload=payload,
                            param_name='path'
                        )
                    )
                for future in as_completed(futures):
                    if not scan_active:
                        break
                    try:
                        if future.result():
                            found_vulnerabilities += 1
                            vulnerable_urls.append(urllib.parse.urlunparse(test_url))
                    except Exception as e:
                        if scan_active:
                            print(Fore.RED + f"[!] Error testing path: {str(e).splitlines()[0]}")
            else:
                query_params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        query_params[key] = [value]
                    else:
                        query_params[param] = ['']
                print(Fore.YELLOW + f"\n[i] Query Params: {query_params}")
                print(Fore.GREEN + f"\n[i] Found parameters: {', '.join(query_params.keys())}")
                executor = ThreadPoolExecutor(max_workers=max_threads)
                futures = []
                for payload in payloads:
                    if not scan_active:
                        break
                    payload = payload.strip()
                    if not payload:
                        continue
                    for param in query_params:
                        if not scan_active:
                            break
                        modified_params = query_params.copy()
                        modified_params[param] = [payload]
                        test_url = urllib.parse.urlunparse(
                            parsed._replace(
                                query=urllib.parse.urlencode(modified_params, doseq=True)
                            )
                        )
                        futures.append(
                            executor.submit(
                                check_payload_with_selenium, 
                                test_url, 
                                payload, 
                                param
                            )
                        )
                for future in as_completed(futures):
                    if not scan_active:
                        break
                    try:
                        if future.result():
                            found_vulnerabilities += 1
                            vulnerable_urls.append(test_url)
                    except Exception as e:
                        if scan_active:
                            print(Fore.RED + f"[!] Error testing parameter: {str(e).splitlines()[0]}")
        except KeyboardInterrupt:
            print(Fore.MAGENTA + "\nPlease wait, cleaning up resources...")
            scan_active = False
            stop_event.set()
            for driver in drivers:
                try:
                    driver.quit()
                except:
                    pass
            drivers.clear()
            if executor is not None:
                executor.shutdown(wait=False, cancel_futures=True)
            print(Fore.YELLOW + "[!] Scan interrupted by user.")
            if scan_state and scan_state.get('vulnerability_found', False):
                print(Fore.GREEN + f"\n[+] Partial results - Vulnerabilities found: {scan_state.get('total_found', 0)}")
                if scan_state.get('vulnerable_urls'):
                    print(Fore.GREEN + "[+] Vulnerable URLs:")
                    for url in scan_state['vulnerable_urls']:
                        print(Fore.GREEN + f"    {url}")
            else:
                print(Fore.YELLOW + "\n[-] Scan cancelled before completion")
            raise KeyboardInterrupt
        finally:
            if executor is not None:
                executor.shutdown(wait=False)
            for driver in drivers:
                try:
                    driver.quit()
                except:
                    pass
            drivers.clear()
        return found_vulnerabilities, vulnerable_urls

    def get_file_path(prompt_text):
        if not scan_active:
            return None
        completer = PathCompleter()
        try:
            return prompt(prompt_text, completer=completer).strip()
        except:
            return None

    def prompt_for_urls():
        while scan_active:
            try:
                url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL): ")
                if not scan_active:
                    return None
                if url_input is None:
                    return None
                if url_input:
                    if not os.path.isfile(url_input):
                        print(Fore.RED + f"[!] File not found: {url_input}")
                        continue
                    with open(url_input) as file:
                        urls = [line.strip() for line in file if line.strip()]
                    return urls
                else:
                    single_url = input(Fore.BLUE + "[?] Enter a single URL to scan: ").strip()
                    if single_url:
                        return [single_url]
                    print(Fore.RED + "[!] You must provide either a file with URLs or a single URL")
            except Exception as e:
                print(Fore.RED + f"[!] Error: {str(e)}")
                if not scan_active:
                    return None
                if input(Fore.YELLOW + "[i] Press Enter to try again or 'q' to quit: ").strip().lower() == 'q':
                    return None

    def prompt_for_payloads():
        while scan_active:
            try:
                payload_input = get_file_path("[?] Enter the path to the payloads file: ")
                if not scan_active:
                    return None
                if payload_input is None:
                    return None
                if not os.path.isfile(payload_input):
                    print(Fore.RED + f"[!] File not found: {payload_input}")
                    continue
                with open(payload_input, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip()]
                return payloads
            except Exception as e:
                print(Fore.RED + f"[!] Error: {str(e)}")
                if not scan_active:
                    return None
                if input(Fore.YELLOW + "[i] Press Enter to try again or 'q' to quit: ").strip().lower() == 'q':
                    return None

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

    def save_results(vulnerable_urls, total_found, total_scanned, start_time):
        if not scan_active:
            return
        if vulnerable_urls:
            try:
                generate_report = input(f"{Fore.CYAN}\n[?] Vulnerabilities found! Generate HTML report? (y/n): ").strip().lower()
                if generate_report == 'y':
                    html_content = generate_html_report("Open Redirect (OR)", total_found, total_scanned, int(time.time() - start_time), vulnerable_urls)
                    filename = input(f"{Fore.CYAN}[?] Enter filename (or press Enter for default): ").strip()
                    if not filename:
                        filename = f"open_redirect_report_{int(time.time())}.html"
                    report_file = save_html_report(html_content, filename)
                    if report_file:
                        print(Fore.GREEN + f"[✓] Report saved to: {report_file}")
            except:
                pass
        elif total_scanned > 0:
            print(Fore.YELLOW + "\n[i] No vulnerabilities found.")
        else:
            print(Fore.RED + "[!] No URLs were scanned.")

    clear_screen()
    panel = Panel(r"""
     ____  ___    ____________   _  ___  __________
    / __ \/ _ \  / __/ ___/ _ | / |/ / |/ / __/ _  |
   / /_/ / , _/ _\ \/ /__/ __ |/    /    / _// , _/
  /____//_/|_| /___/\___/_/ |_/_/|_/_/|_/___/_/|_| 
            
                            """,
        style="bold green",
        border_style="blue",
        expand=False
    )
    rich_print(panel, "\n")
    print(Fore.GREEN + "Welcome to the Open Redirect Testing Tool!\n")
    try:
        urls = prompt_for_urls()
        payloads = prompt_for_payloads()
        max_threads_input = input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip()
        max_threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 10 else 5
        print(Fore.YELLOW + "\n[i] Loading, Please Wait...")
        clear_screen()
        print(Fore.CYAN + "[i] Starting scan...\n")
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
                current_scan_state = {
                    'vulnerability_found': False,
                    'vulnerable_urls': [],
                    'total_found': 0,
                    'total_scanned': 0
                }
                box_content = f" → Scanning URL: {url} "
                box_width = max(len(box_content) + 2, 40)
                print(Fore.YELLOW + "\n┌" + "─" * (box_width - 2) + "┐")
                print(Fore.YELLOW + f"│{box_content.center(box_width - 2)}│")
                print(Fore.YELLOW + "└" + "─" * (box_width - 2) + "┘\n\n")
                found, urls_with_payloads = test_open_redirect(url, payloads, max_threads)
                total_found += found
                total_scanned += len(payloads)
                vulnerable_urls.extend(urls_with_payloads)
                scan_state['vulnerability_found'] |= current_scan_state['vulnerability_found']
                scan_state['vulnerable_urls'].extend(current_scan_state['vulnerable_urls'])
                scan_state['total_found'] += current_scan_state['total_found']
                scan_state['total_scanned'] += current_scan_state['total_scanned']
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
    except KeyboardInterrupt:
        print(Fore.MAGENTA + "Please wait, the threads will stop working in a few seconds...")
        stop_event.set()
        sleep(2)
        executor.shutdown(wait=True)
        print(Fore.YELLOW + "[!] Stopped all threads.")
        print(Fore.RED + "\n[!] Scan interrupted by user.")
        if scan_state and scan_state['vulnerability_found']:
            print(Fore.GREEN + f"\n[+] Vulnerabilities found: {scan_state['total_found']}")
            print(Fore.GREEN + f"[+] Vulnerable URLs:")
            for url in scan_state['vulnerable_urls']:
                print(Fore.GREEN + f"    {url}")
        else:
            print(Fore.YELLOW + "\n[-] No vulnerabilities found.")
            print(Fore.CYAN + f"\n[i] Total URLs scanned: {scan_state['total_scanned']}")
        sys.exit()
