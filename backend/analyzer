import re
import sys
from typing import Dict, List


class SimplePhishingAnalyzer:
    def __init__(self):
        self.trusted_domains = [
            'axis.mu', 'blc.mu', 'axisfiduciary.mu',
        ]
        self.indicators    = []
        self.risk_score    = 0
        self._from_trusted = False

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def analyze(self, email_text: str, attachments: List[Dict] = None) -> Dict:
        """
        Analyze an Outlook-formatted email for phishing indicators.
        
        Args:
            email_text: Full email content including headers and body
            attachments: List of attachment dicts with 'name' and 'size' keys
        """
        self.indicators    = []
        self.risk_score    = 0
        self._from_trusted = False

        headers = self._parse_outlook_headers(email_text)

        sender     = headers.get('from',       'Unknown')
        sent       = headers.get('sent',       'Unknown')
        to         = headers.get('to',         'Unknown')
        cc         = headers.get('cc',         'Unknown')
        subject    = headers.get('subject',    'Unknown')
        importance = headers.get('importance', 'Normal')

        # Domain check MUST run first so _from_trusted is set for later checks
        self._check_sender_domain(sender, to, cc)
        self._check_urls(email_text)
        self._check_urgency(email_text, subject)
        self._check_sensitive_info(email_text)
        self._check_generic_greeting(email_text)
        self._check_importance(importance)
        self._check_subject(subject)
        
        # Analyze attachments if provided
        attachment_analysis = None
        if attachments:
            attachment_analysis = self._check_attachments(attachments)

        return {
            'risk_score':  self.risk_score,
            'risk_level':  self._get_risk_level(),
            'is_phishing': self.risk_score >= 40,
            'indicators':  self.indicators,
            'sender':      sender,
            'sent':        sent,
            'to':          to,
            'cc':          cc,
            'subject':     subject,
            'importance':  importance,
            'attachments': attachment_analysis,
        }

    # ------------------------------------------------------------------
    # Outlook header parser
    # ------------------------------------------------------------------
    def _parse_outlook_headers(self, text: str) -> Dict:
        """
        Parses Outlook-style headers (From, Sent, To, Cc, Subject, Importance).
        Returns a dict with lowercase keys.
        """
        pattern = re.compile(
            r'^(From|Sent|To|Cc|Subject|Importance)\s*:\s*(.+)',
            re.IGNORECASE | re.MULTILINE
        )
        headers = {}
        for m in pattern.finditer(text):
            key   = m.group(1).strip().lower()
            value = m.group(2).strip()
            headers[key] = value
        return headers

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------
    def _check_sender_domain(self, sender: str, to: str = '', cc: str = ''):
        """
        1. If From has a full email  -> check its domain directly.
        2. If From has only a display name (no email) -> look for trusted
           addresses in the To / Cc fields as corroborating evidence.
        3. If From is entirely missing -> flag it.

        Sets self._from_trusted which other checks use to scale penalties.
        """
        if sender in ('Unknown', ''):
            self._add_indicator(30, 'Missing Sender',
                'No From field found — cannot verify origin.')
            return

        email = self._extract_email(sender)

        if email and '@' in email:
            # ---- Case 1: From field has a proper email address ----
            domain = email.split('@')[-1].lower()
            if self._is_trusted_domain(domain):
                self._from_trusted = True
                self._add_indicator(-25, 'Trusted Internal Domain',
                    f'Email originates from verified internal domain "{domain}".')
            else:
                self._add_indicator(35, 'Untrusted Domain',
                    f'Domain "{domain}" is not in the trusted list: '
                    f'{[d.lstrip("@") for d in self.trusted_domains]}')
        else:
            # ---- Case 2: Display name only — no email in From ----
            # Look for trusted addresses in To / Cc as supporting evidence
            trusted_recipients = self._find_trusted_emails(to + ' ' + cc)

            if trusted_recipients:
                # Internal email routed to trusted addresses — likely legitimate
                self._from_trusted = True
                self._add_indicator(-10, 'Display Name Only (Trusted Recipients)',
                    f'From field shows display name only ("{sender}"), but email '
                    f'is addressed to verified internal recipients '
                    f'({", ".join(trusted_recipients)}). Likely a legitimate '
                    f'internal email where the full address was hidden by the mail client.')
            else:
                self._add_indicator(20, 'No Email Address in From Field',
                    f'From field "{sender}" shows only a display name with no email '
                    f'address, and no trusted internal recipients were found — '
                    f'a pattern seen in display-name spoofing attacks.')

    def _check_urls(self, text: str):
        """Flag raw IP-based URLs and suspicious TLDs."""
        urls = re.findall(r'https?://[^\s<>")\]]+', text, re.IGNORECASE)
        for url in urls:
            if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
                self._add_indicator(30, 'IP-Based URL',
                    f'URL uses a raw IP address instead of a domain name: {url}')
            suspicious_tlds = ['.xyz', '.top', '.zip', '.tk', '.ml', '.ga', '.cf']
            if any(tld in url.lower() for tld in suspicious_tlds):
                self._add_indicator(25, 'Suspicious TLD',
                    f'URL contains a TLD commonly associated with phishing: {url}')

    def _check_urgency(self, text: str, subject: str = ''):
        """
        Urgency words in the body raise the score.
        Penalty is halved for trusted internal senders — IT teams
        legitimately send urgent security and patch notices.
        """
        urgency_words = [
            'urgent', 'immediately', 'action required', 'verify now',
            'account suspended', 'expire', 'deadline', 'act now',
        ]
        combined = (text + ' ' + subject).lower()
        found = [w for w in urgency_words if w in combined]
        if found:
            penalty = 10 if self._from_trusted else 20
            self._add_indicator(penalty, 'Urgency Language',
                f'Contains urgency words: {", ".join(found)}'
                + (' (reduced penalty — trusted sender)' if self._from_trusted else ''))

    def _check_sensitive_info(self, text: str):
        """Flag requests for credentials or financial data."""
        sensitive = [
            'password', 'credit card', 'bank account', 'pin',
            'ssn', 'verify your', 'confirm your',
        ]
        text_lower = text.lower()
        found = [w for w in sensitive if w in text_lower]
        if found:
            self._add_indicator(30, 'Sensitive Information Request',
                f'Email asks for sensitive data: {", ".join(found)}')

    def _check_generic_greeting(self, text: str):
        """Flag impersonal greetings typical of mass-phishing templates."""
        generic = ['dear customer', 'dear user', 'dear client', 'hello customer']
        text_lower = text.lower()
        for greeting in generic:
            if greeting in text_lower:
                self._add_indicator(15, 'Generic Greeting',
                    f'Uses a generic, impersonal greeting: "{greeting}"')
                break

    def _check_importance(self, importance: str):
        """
        High Importance is a social-engineering pressure tactic.
        Penalty is much lower when the sender is a trusted internal domain.
        """
        if importance.strip().lower() == 'high':
            penalty = 5 if self._from_trusted else 15
            self._add_indicator(penalty, 'High Importance Flag',
                'Email is marked Importance: High'
                + (' (minor flag — trusted sender)' if self._from_trusted else
                   ' — a common social-engineering pressure tactic.'))

    def _check_subject(self, subject: str):
        """
        Flag high-pressure subject lines.
        Penalty is halved for trusted internal senders.
        """
        pressure_words = [
            'urgent', 'immediate', 'action required', 'mandatory',
            'critical', 'important', 'verify', 'suspended', 'alert',
        ]
        subject_lower = subject.lower()
        found = [w for w in pressure_words if w in subject_lower]
        if found:
            penalty = 5 if self._from_trusted else 15
            self._add_indicator(penalty, 'High-Pressure Subject Line',
                f'Subject contains pressure keywords: {", ".join(found)}'
                + (' (reduced penalty — trusted sender)' if self._from_trusted else ''))

    def _check_attachments(self, attachments: List[Dict]) -> Dict:
        """
        Analyze email attachments for suspicious characteristics.
        
        Args:
            attachments: List of dicts with 'name' and 'size' keys
        
        Returns:
            Dict with attachment analysis results
        """
        suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.msi', '.dll',
            '.zip', '.rar', '.7z', '.tar', '.gz'
        ]
        
        dangerous_double_extensions = [
            '.exe.zip', '.scr.zip', '.bat.zip', '.cmd.zip',
            '.doc.exe', '.pdf.exe', '.xls.exe', '.ppt.exe',
            '.doc.scr', '.pdf.scr', '.xls.scr'
        ]
        
        analysis = {
            'total_count': len(attachments),
            'suspicious_count': 0,
            'safe_count': 0,
            'details': []
        }
        
        for attachment in attachments:
            name = attachment.get('name', '').lower()
            size = attachment.get('size', 0)
            
            attachment_result = {
                'name': attachment.get('name', 'Unknown'),
                'size': size,
                'is_suspicious': False,
                'reasons': []
            }
            
            # Check for suspicious extensions
            for ext in suspicious_extensions:
                if name.endswith(ext):
                    attachment_result['is_suspicious'] = True
                    attachment_result['reasons'].append(
                        f'Has suspicious file extension: {ext}'
                    )
                    self._add_indicator(25, 'Suspicious Attachment Extension',
                        f'Attachment "{attachment.get("name")}" has dangerous extension: {ext}')
            
            # Check for double extensions (hiding executable)
            for double_ext in dangerous_double_extensions:
                if name.endswith(double_ext):
                    attachment_result['is_suspicious'] = True
                    attachment_result['reasons'].append(
                        f'Has dangerous double extension: {double_ext}'
                    )
                    self._add_indicator(35, 'Double Extension Attachment',
                        f'Attachment "{attachment.get("name")}" uses double extension to hide malicious file: {double_ext}')
            
            # Check for very large attachments (potential data exfiltration or malware)
            if size > 50 * 1024 * 1024:  # 50MB
                attachment_result['is_suspicious'] = True
                attachment_result['reasons'].append(
                    f'Unusually large attachment: {size / (1024*1024):.1f}MB'
                )
                self._add_indicator(15, 'Large Attachment',
                    f'Attachment "{attachment.get("name")}" is unusually large: {size / (1024*1024):.1f}MB')
            
            # Check for password-protected archive patterns
            if any(x in name for x in ['password', 'protected', 'encrypted', 'secret']):
                attachment_result['is_suspicious'] = True
                attachment_result['reasons'].append(
                    'Filename suggests password protection'
                )
                self._add_indicator(20, 'Password-Protected Archive',
                    f'Attachment "{attachment.get("name")}" appears to be password-protected, which is common in malware delivery.')
            
            if attachment_result['is_suspicious']:
                analysis['suspicious_count'] += 1
            else:
                analysis['safe_count'] += 1
            
            analysis['details'].append(attachment_result)
        
        # If multiple suspicious attachments, add additional indicator
        if analysis['suspicious_count'] >= 2:
            self._add_indicator(15, 'Multiple Suspicious Attachments',
                f'Email contains {analysis["suspicious_count"]} suspicious attachments.')
        
        return analysis

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _is_trusted_domain(self, domain: str) -> bool:
        """Return True if domain matches any entry in trusted_domains."""
        for t in self.trusted_domains:
            t_clean = t.lstrip('@')
            if domain == t_clean or domain.endswith('.' + t_clean):
                return True
        return False

    def _find_trusted_emails(self, text: str) -> List[str]:
        """Return all email addresses in text whose domain is trusted."""
        all_emails = re.findall(r'[\w\.\-+]+@[\w\.\-]+\.\w+', text)
        return [e for e in all_emails if self._is_trusted_domain(e.split('@')[-1].lower())]

    def _extract_email(self, text: str) -> str:
        """Extract bare email from 'Name <email@domain>' or plain address."""
        angle = re.search(r'<([\w\.\-+]+@[\w\.\-]+\.\w+)>', text)
        if angle:
            return angle.group(1).strip()
        bare = re.search(r'[\w\.\-+]+@[\w\.\-]+\.\w+', text)
        if bare:
            return bare.group(0).strip()
        return ''

    def _add_indicator(self, score: int, title: str, explanation: str):
        self.indicators.append({
            'score':       score,
            'title':       title,
            'explanation': explanation,
        })
        self.risk_score += score

    def _get_risk_level(self) -> str:
        if self.risk_score >= 50: return 'HIGH'
        if self.risk_score >= 30: return 'MEDIUM'
        if self.risk_score >= 15: return 'LOW'
        return 'SAFE'
