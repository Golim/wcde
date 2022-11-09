#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2022 Matteo Golinelli"
__license__ = "MIT"

from requests.exceptions import SSLError, ConnectionError, ReadTimeout, TooManyRedirects, ChunkedEncodingError, InvalidHeader
from urllib3.exceptions import NewConnectionError, MaxRetryError, ReadTimeoutError
from urllib.parse import urlparse, urlunparse, urljoin, urldefrag
from bs4 import BeautifulSoup

import traceback
import argparse
import requests
import random
import string
import glob
import json
import time
import sys
import os
import re

# =============================================================================
# =============================================================================
# ============================== GLOBAL VARIABLES =============================
# =============================================================================
# =============================================================================

class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    UNDERLINE = '\033[4m'

# CONSTANTS
DEBUG = False
SITE  = ''
MODES = {}
MAX   = 50 # Default maximum number of URLs to visit for each domain
MAX_DOMAINS = 10 # Maximum number of subdomains to crawl
EXTENSIONS = ['.css']
LOGS  = 'logs'
STATS = 'stats'
HTML  = 'html'

# Avoid accessing potentially large files
EXCLUDED_EXTENSIONS = set([
    '.webm', '.m3u', '.m3u8', '.pls', '.cue', '.wpl', '.asx', '.xspf', '.mpd'
    '.ps', '.tif', '.tiff', '.ppt', '.pptx', '.xls', '.xlsx', '.dll', '.msi',
    '.iso', '.sql', '.apk', '.jar', '.bmp', '.gif', '.jpg', '.jpeg', '.png',
    '.zip', '.exe', '.dmg', '.doc', '.docx', '.odt', '.pdf', '.rtf', '.tex',
    '.mpg', '.mpeg', '.avi', '.mov', '.wmv', '.flv', '.swf', '.mp4', '.m4v',
    '.mp3', '.ogg', '.wav', '.wma', '.7z', '.rpm', '.gz', '.tar', '.deb',
])

USER_AGENT = f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/53' + \
    f'{random.randint(1, 9)}.{random.randint(1, 40)} (KHTML, like Gecko)' + \
    f'Chrome/103.0.0.{random.randint(0, 15)} Safari/537.{random.randint(1, 50)}'

BLACKLISTED_DOMAINS = [
    'doubleclick.net', 'googleadservices.com',
    'google-analytics.com', 'googletagmanager.com',
    'googletagservices.com', 'googleapis.com',
    'googlesyndication.com', 'analytics.ticktok.com',
    'gstatic.com',
]

# Python requests browser with the user agent
class Browser:
    def __init__(self, cookies=None):
        if cookies:
            self.session = requests.Session()

            cookie_jar = requests.cookies.RequestsCookieJar()
            for cookie in cookies:
                cookie_jar.set(
                    cookie['name'],
                    cookie['value'],
                    domain=(cookie['domain'] if 'domain' in cookie else None),
                    path=(cookie['path'] if 'path' in cookie else None),
                    expires=(cookie['expires'] if 'expires' in cookie else None),
                    secure=(cookie['secure'] if 'secure' in cookie else None),
                    rest={'HttpOnly': (cookie['httpOnly'] if 'httpOnly' in cookie else None)},
                )
            self.session.cookies = cookie_jar
        else:
            self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
    def get(self, url, **kwargs):
        if 'referrer' in kwargs:
            self.session.headers.update({'Referer': kwargs['referrer']})
        else:
            self.session.headers.pop('Referer', None)
        kwargs.pop('referrer', None)
        return self.session.get(url, **kwargs)

# Dictionaries where the key is the domain and the value is a list of URLs
queue = {}
visited_urls = {}

# Statistics dictionary
statistics = {
    'site':         SITE,
    'vulnerable':   False,
    'diff':         False, # Found at least one URL that has dynamic content
    'modes':        [],
    'codes':        [],
    'vulnerabilities': {}, # for each mode saves the vulnerable URLs
}

# =============================================================================
# =============================================================================
# ================================= FUNCTIONS =================================
# =============================================================================
# =============================================================================

# =============================================================================
# ========================= Basic crawling functions ==========================
# =============================================================================

def get_template_url(url):
    """
    Returns the template of the passed URL. The template contains:
    - the netloc (domain)
    - the path
    Everything else is removed.
    """
    parsed = urlparse(url)
    return urlunparse(('', parsed.netloc, re.sub('\d+', '', parsed.path), '', '', ''))

def get_domain_name(url):
    """
    Returns the domain name of the passed URL
    (Ignore top level domain and subdomains).
    """
    if url.startswith('http') and '//' in url:
        parsed = urlparse(urldefrag(url)[0])
        split_netloc = parsed.netloc.replace('www.', '').split('.')
    else:
        split_netloc = url.split('.')
    if len(split_netloc) > 2:
        if len(split_netloc[-2]) > 3:
            return split_netloc[-2]
        else:
            return split_netloc[-3]
    elif len(split_netloc) == 2:
        return split_netloc[-2]
    else:
        return ''

def get_domain(url):
    """
    Returns the domain name of the passed URL.
    """
    return urlparse(url).netloc

def is_internal_url(url):
    """
    Returns True if the url is internal to the website.
    Subdomains are considered internal.
    """
    if not url.startswith('http'):
        url = 'http://' + url
    parsed = urlparse(url)
    if parsed.netloc.endswith(SITE):
        return True
    else:
        return False

def get_links(page_url, html, only_internal=True):
    """
    Receives a URL and the body of the web page
    and returns a set of all links found in the
    page that are internal (meaning that are on
    the same site)
    """
    links = []

    soup = BeautifulSoup(html, 'html.parser')

    for link in soup.find_all('a', href=True):
        url = urljoin(clean_url(page_url), clean_url(link['href']))

        if 'http' in url and only_internal and is_internal_url(url):
            links.append(clean_url(urldefrag(url)[0]))

        elif not only_internal:
            _url = clean_url(urldefrag(url)[0])
            if any([i in _url for i in BLACKLISTED_DOMAINS]):
                continue

            links.append(_url)

    return links

def add_to_queue(url):
    """
    Add a url to the queue if it is not already in the queue
    and if its template is not already in the visited list.
    """
    domain  = get_domain(url)

    if not is_visited(url):
        if domain not in queue and \
            len(queue) < MAX_DOMAINS:
            queue[domain] = []

        if domain in queue and \
            url not in queue[domain]:
            queue[domain].append(url)

def add_to_visited(url):
    """
    Add a url to the visited list.
    """
    if not is_visited(url):
        domain  = get_domain(url)
        if domain not in visited_urls:
            visited_urls[domain] = []

        template_url = get_template_url(url)
        visited_urls[domain].append(template_url)

def is_visited(url):
    """
    Return True if the template of the url
    is in the visited list.
    """
    domain  = get_domain(url)
    if not domain in visited_urls:
        return False

    template_url = get_template_url(url)
    if template_url is not None and \
        template_url in visited_urls[domain]:
        return True
    else:
        return False

def get_url_from_queue(visited=False):
    """
    Return the first not visited url in the queue
    if the visited list for this domain is not full.
    """
    domains = list(queue.keys())
    random.shuffle(domains)

    for domain in domains:
        # If the visited list for this domain
        # is full, choose a new domain
        if domain in visited_urls and \
            len(visited_urls[domain]) >= MAX:
            continue
        else:
            # Pop the first url in the queue
            # for this domain
            while len(queue[domain]) > 0:
                url = queue[domain].pop(0)
                if not is_visited(url):
                    if visited:
                        add_to_visited(url)
                    return url
    return None

def should_continue():
    """
    Return True if the queue is not empty
    and the visited list is not full.
    """
    for domain in queue:
        if domain not in visited_urls or \
            (len(visited_urls[domain]) < MAX and \
                len(queue[domain]) > 0):
            return True
    return False

# =============================================================================
# ============================== WCD functions ================================
# =============================================================================

def generate_attack_url(url, mode, extension='.css'):
    '''
    Generate the attack URL including the
    desired path confusion technique in
    the passed URL.

    For different path confusion variations
    the inclusion happens in different places
    of the URL.
    '''
    parsed_url    = urlparse(url)
    random_string = get_random_string()
    encoded_character = MODES[mode]

    path  = parsed_url.path
    query = parsed_url.query
    # Path parameter / is simply appended at the end
    if mode == 'PATH_PARAMETER':
        if not path.endswith('/'):
            path += encoded_character
        path += f'{random_string}{extension}'

    # Encoded question mark ? is placed before the query string
    elif mode == 'ENCODED_QUESTION':
        path += f'{encoded_character}{query}{random_string}{extension}'
        query = ''

    else:
        path += f'{encoded_character}{random_string}{extension}'

    return urlunparse(
        (parsed_url.scheme, parsed_url.netloc,
        path, parsed_url.params, query, parsed_url.fragment)
    )

def cache_headers_heuristics(headers):
    '''
    Inspects HTTP response headers to heuristically
    determine whether a request is served from the
    origin server or a web cache

    Returns a 'HIT' or 'MISS' for cache and origin
    respectively.
    '-' if the status is unknown.
    '''
    for header in headers:
        if 'cache' in header.lower() or\
            'server-timing' in header.lower():
            # Order of the checks matters
            if 'hit' in headers[header].lower():
                return 'HIT'
            elif 'miss' in headers[header].lower():
                return 'MISS'

        if 'cache' in header.lower() or\
            'server-timing' in header.lower():
            if 'cached' in headers[header].lower():
                return 'HIT'
            elif 'caching' in headers[header].lower():
                return 'MISS'
    return '-'

def identicality_checks(p1, p2):
    '''
    Compare two web pages.
    Return False is the pages are different
    (i.e., contain dynamic content) 
    True if the pages are 100% identical
    '''
    if p1 == p2:
        return True
    else:
        return False

# =============================================================================
# ============================= Helper functions ==============================
# =============================================================================

def log(message='', file=sys.stdout, end='\n'):
    print(f'[LOG {SITE}] {message}', file=file, end=end, flush=True)

def debug(message, file=sys.stderr, end='\n'):
    if DEBUG:
        print(f'[DEBUG {SITE}] {message}', file=file, end=end, flush=True)

def clean_url(url):
    """
    Cleans the url to remove any trailing newlines and spaces.
    """
    return url.strip().strip('\n')

def encode(s):
    '''
    URL-encode characters or strings
    '''
    return ''.join(['%' + hex(ord(i)).replace('0x', '').upper().zfill(2) for i in s])

def get_random_string(_min=10, _max=20):
    '''
    Generates a random string of random
    length between 10 and 20 characters
    '''
    return ''.join(
        random.choice(string.ascii_lowercase + string.digits + '_')
        for _ in range(random.randint(_min, _max))
    )

def log_site_statistics(statistics):
    if statistics['vulnerable']:
        log(f'Website {statistics["site"]} is vulnerable to {", ".join(statistics["modes"])}')
        for vulnerability in statistics['vulnerabilities']:
            log(f'{vulnerability}: {statistics["vulnerabilities"][vulnerability]}')
    else:
        log(f'Website {statistics["site"]} is not vulnerable')

def diff_lines(a, b):
    '''
    Returns the lines that differ between two
    multi-lines strings (pages HTML code)
    '''
    a = a.split('\n')
    b = b.split('\n')
    res = ''
    for i in range(min(len(a), len(b))):
        _a, _b = a[i].strip(), b[i].strip()
        if _a == '' and _b == '':
            continue
        if _a != _b:
            res += f'< {_a}\n'
            res += f'> {_b}\n'
    res += '---'
    return res

def save_dictionaries():
    """
    Save the dictionaries to files.
    """
    global statistics, visited_urls, queue

    logs = {
        'queue':        queue,
        'visited':      visited_urls
    }

    with open(f'{LOGS}/{SITE}-logs.json', 'w') as f:
        json.dump(logs, f, indent=4)
    with open(f'{STATS}/{SITE}-statistics.json', 'w') as f:
        json.dump(statistics, f, indent=4)

def get_dictionaries():
    """
    Load the dictionaries from the files.
    """
    global statistics, visited_urls, queue

    try:
        if os.path.exists(f'{LOGS}/{SITE}-logs.json'):
            with open(f'{LOGS}/{SITE}-logs.json', 'r') as f:
                logs = json.load(f)
                queue = logs['queue']
                visited_urls = logs['visited']
    except:
        pass # The file might be empty, or the JSON broken
    try:
        if os.path.exists(f'{STATS}/{SITE}-statistics.json'):
            with open(f'{STATS}/{SITE}-statistics.json', 'r') as f:
                statistics = json.load(f)
    except:
        pass

# =============================================================================
# =============================================================================
# =================================== MAIN ====================================
# =============================================================================
# =============================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='wcde.py',
        description='Implementation of the detection methodology for ' + \
                    'Web Cache Deception vulnerabilities in a target website')

    parser.add_argument('-t', '--target',
        help='Target website', required=True)

    parser.add_argument('-c', '--cookie',
        help='Cookies JSON file to use for the requests')

    parser.add_argument('-m', '--max',      default=MAX,
        help=f'Maximum number of URLs to test for each domain/subdomain (default: {MAX})')

    parser.add_argument('-d', '--domains',  default=MAX_DOMAINS,
        help=f'Maximum number of domains/subdomains to test(default: {MAX_DOMAINS})')

    parser.add_argument('-e', '--extensions', default=EXTENSIONS,
        help=f'Extension(s) to use when crafting the attack URLs (default: {EXTENSIONS[0]}). ' + \
            f'Use commas to separate multiple extensions')

    parser.add_argument('-p', '--path-confusion',
        help='JSON file containing the path confusion techniques to use (key-value: name-character)')

    parser.add_argument('-D', '--debug',    action='store_true',
        help='Enable debug mode')

    args = parser.parse_args()

    SITE    = args.target.strip()
    MAX   = int(args.max)

    if args.debug:
        DEBUG = True

    if args.cookie:
        cookies_file_name = args.cookie

        with open(cookies_file_name, 'r') as f:
            cookies = json.load(f)

    if args.extensions:
        EXTENSIONS = []
        for extension in args.extensions.split(','):
            extension = extension.strip()
            EXTENSIONS.append(extension if extension.startswith('.') else '.' + extension)

    if args.path_confusion:
        path_confusion_file_name = args.path_confusion

        with open(path_confusion_file_name, 'r') as f:
            path_confusion = json.load(f)
        for name in path_confusion:
            MODES[name.strip()] = path_confusion[name].strip()
    else:
        # Default path confusion techniques
        MODES = {
            'PATH_PARAMETER'    : '/',
            'ENCODED_SEMICOLON' : encode(';'),    # %3B
            'ENCODED_QUESTION'  : encode('?'),    # %3F
            'ENCODED_NEWLINE'   : encode('\n'),   # %0A
            'ENCODED_SHARP'     : encode('#'),    # %23
            'ENCODED_SLASH'     : encode('/'),    # %2F
            # 'ENCODED_NULL'      : encode('\x00'), # %00
            'DOUBLE_ENCODED_SEMICOLON': encode('%3B'), # %25%33%42
            'DOUBLE_ENCODED_QUESTION':  encode('%3F'), # %25%33%46
            'DOUBLE_ENCODED_NEWLINE':   encode('%0A'), # %25%30%41
            'DOUBLE_ENCODED_SHARP':     encode('%23'), # %25%32%33
            'DOUBLE_ENCODED_SLASH':     encode('%2F'), # %25%32%46
            'DOUBLE_ENCODED_NULL':      encode('%00'), # %25%30%30
        }

    if not os.path.exists(LOGS):
        os.mkdir(LOGS)
    if not os.path.exists(STATS):
        os.mkdir(STATS)
    if not os.path.exists(HTML):
        os.mkdir(HTML)

    random.seed(42)

    statistics['site'] = SITE

    log('Started testing for unauthenticated WCD')

    # Load the dictionaries from the files if they exist
    get_dictionaries()

    for scheme in ['http', 'https']:
        add_to_queue(f'{scheme}://{SITE}')
        add_to_queue(f'{scheme}://www.{SITE}')

    if not should_continue():
        sys.exit(0)

    if args.cookie:
        log('Using provided cookies to create the victim\'s session.')
        victim_browser   = Browser(cookies=cookies)
    else:
        victim_browser   = Browser()
    attacker_browser = Browser()

    while should_continue():
        try:
            url = get_url_from_queue()

            if url is None:
                break

            if is_visited(url):
                continue

            parsed = urlparse(url)
            if any(parsed.path.endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                continue

            # Check if the URL accessed two times gives different responses
            victim_response   =   victim_browser.get(url)
            attacker_response = attacker_browser.get(url)

            links = get_links(victim_response.url, victim_response.text)
            for link in links:
                add_to_queue(link)

            if not identicality_checks(victim_response.text, attacker_response.text):
                statistics['diff'] = True

                for extension in EXTENSIONS:
                    for mode in MODES:
                        url1 = generate_attack_url(url, mode, extension)
                        url2 = generate_attack_url(url, mode, extension)

                        victim_response =   victim_browser.get(url1, referrer=url)
                        test_response   = attacker_browser.get(url2, referrer=url)

                        if not identicality_checks(victim_response.text, test_response.text) and\
                                cache_headers_heuristics(victim_response.headers) == 'MISS':
                            attacker_response = attacker_browser.get(url1, referrer=url)

                            #output[mode]['url'] = url1
                            if identicality_checks(victim_response.text, attacker_response.text) and\
                                    cache_headers_heuristics(attacker_response.headers) == 'HIT':
                                statistics['vulnerable'] = True

                                # Dump differences if the site is vulnerable
                                diff = diff_lines(victim_response.text, test_response.text)
                                with open(f'{HTML}/{SITE}.diff.txt', 'a') as f:
                                    print(f'== < {url1}', file=f)
                                    print(f'== > {url2}', file=f)
                                    print(diff, file=f)

                                add_to_visited(url) # Mark the URL as visited if it is vulnerable
                                print(f'[Warning] {SITE} vulnerable {mode}: {bcolors.FAIL}{url1}' +
                                    f'{bcolors.ENDC} code {attacker_response.status_code}', flush=True)

                                if not mode in statistics['modes']:
                                    statistics['modes'].append(mode)
                                if not attacker_response.status_code in statistics['codes']:
                                    statistics['codes'].append(attacker_response.status_code)
                                if not mode in statistics['vulnerabilities']:
                                    statistics['vulnerabilities'][mode] = []
                                statistics['vulnerabilities'][mode].append([url, url1, attacker_response.status_code])

            add_to_visited(url)
            # time.sleep(2) # Wait x seconds between two tests to limit the stress on the server

        except KeyboardInterrupt:
            break
        except (SSLError, NewConnectionError, MaxRetryError, ConnectionError,
                ReadTimeoutError, ReadTimeout, TooManyRedirects, ChunkedEncodingError, InvalidHeader):
            debug(f'{url}')
            pass
        except Exception as e:
            log(f'ERROR: {url} -> {e}')
            debug(traceback.format_exc())

    # Save dictionaries to files
    save_dictionaries()

    # Print final statistics for website
    log_site_statistics(statistics)
