/* Ask ignixip — client-side question router. No network, no model. */
(function (root) {
    function isIPv4(str) {
        return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(str) && str.split('.').every(function (p) { return parseInt(p, 10) <= 255; });
    }

    function isIPv6(str) {
        return /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(str) || /^::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$/.test(str) || /^([0-9a-fA-F]{1,4}:){1,6}:$/.test(str) || /^::$/.test(str);
    }

    function blankSpans(text, spans) {
        var chars = text.split('');
        spans.forEach(function (span) {
            for (var i = span.start; i < span.end && i < chars.length; i++) chars[i] = ' ';
        });
        return chars.join('');
    }

    function collect(re, text, spans) {
        var out = [];
        var source = blankSpans(text, spans);
        re.lastIndex = 0;
        var m;
        while ((m = re.exec(source))) {
            var raw = m[0];
            var start = m.index;
            var end = start + raw.length;
            out.push({ raw: raw, start: start, end: end, groups: m });
            spans.push({ start: start, end: end });
            if (m.index === re.lastIndex) re.lastIndex++;
        }
        return out;
    }

    function cleanHost(host) {
        return String(host || '').replace(/^\.+|\.+$/g, '').replace(/[),.;:!?]+$/g, '').toLowerCase();
    }

    function hostFromUrl(url) {
        var rest = String(url).replace(/^https?:\/\//i, '');
        var host = rest.split('/')[0].split('?')[0].split('#')[0].split(':')[0];
        return cleanHost(host);
    }

    function extractEntities(question) {
        var text = String(question || '');
        var spans = [];
        var urls = collect(/https?:\/\/[^\s<>"']+/gi, text, spans).map(function (m) {
            return m.raw.replace(/[),.;:!?]+$/g, '');
        });
        var emails = collect(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi, text, spans).map(function (m) {
            return m.raw.replace(/[),.;:!?]+$/g, '').toLowerCase();
        });
        var cidrs = collect(/(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}/g, text, spans).map(function (m) { return m.raw; }).filter(function (c) {
            var bits = parseInt(c.split('/')[1], 10);
            return isIPv4(c.split('/')[0]) && bits >= 0 && bits <= 32;
        });
        var v6 = collect(/(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}/gi, text, spans).map(function (m) { return m.raw; }).filter(isIPv6);
        var v4 = collect(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, text, spans).map(function (m) { return m.raw; }).filter(isIPv4);
        var asns = collect(/\bAS\s?(\d{1,10})\b/gi, text, spans).map(function (m) {
            return 'AS' + m.groups[1];
        });
        var domains = collect(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi, text, spans).map(function (m) {
            return cleanHost(m.raw);
        }).filter(function (d) { return d.indexOf('.') > 0 && !/^\d+(\.\d+)+$/.test(d); });

        var emailDomains = emails.map(function (e) { return e.split('@')[1]; }).filter(Boolean);
        var urlHosts = urls.map(hostFromUrl).filter(function (h) { return h && h.indexOf('.') > 0 && !isIPv4(h); });
        var allDomains = domains.concat(emailDomains).concat(urlHosts).filter(function (d, i, arr) { return d && arr.indexOf(d) === i; });

        return {
            urls: urls,
            url: urls[0] || '',
            emails: emails,
            email: emails[0] || '',
            cidrs: cidrs,
            cidr: cidrs[0] || '',
            ips: v4.concat(v6),
            ip: (v4.concat(v6))[0] || '',
            asns: asns,
            asn: asns[0] || '',
            domains: allDomains,
            domain: allDomains[0] || ''
        };
    }

    function intentsOf(question) {
        var q = String(question || '');
        return {
            myip: /what(?:'s| is) my ip|my ip address|my public ip|what ip am i/i.test(q),
            mail: /\b(mx|spf|dkim|dmarc|mail|email|e-mail|spoof|sender)\b/i.test(q),
            blacklist: /\b(blacklist|blacklisted|blocklist|blocklisted|dnsbl|spam)\b|\blisted\b/i.test(q),
            safe: /\b(safe|legit|legitimate|spoof|spoofed|suspicious|malicious)\b/i.test(q),
            whois: /who owns|who registered|whose (?:network|address|domain)|whois|\bregistrar\b|\bregistered\b|how old|domain age|\bage\b/i.test(q),
            asn: /\b(asn|autonomous system|\bisp\b)\b|what network|which network|whose network/i.test(q),
            location: /\b(where|location|geolocation|geo-location)\b|\b(country|city)\b/i.test(q),
            dns: /\b(dns|txt|cname|nameserver|name server)\b|dns records|a records?|ns records?|mx records?/i.test(q),
            url: /\b(phishing|phish)\b|suspicious link|safe to (?:open|click)|is this (?:link|url)|malware/i.test(q),
            tools: /\b(ping|traceroute|tracerout|port scan|open ports)\b|network tools/i.test(q)
        };
    }

    function addTool(tools, tab, value, label) {
        if (tab !== 'myip' && !value) return;
        var key = tab + '|' + value;
        if (tools.some(function (t) { return t.key === key; })) return;
        tools.push({ tab: tab, value: value, label: label, key: key });
    }

    function subjectOf(entities) {
        return entities.email || entities.domain || entities.url || entities.cidr || entities.asn || entities.ip || '';
    }

    function summaryFor(intents, entities, tools) {
        var subject = subjectOf(entities);
        if (intents.myip) return 'Looking up the public IP address of this connection.';
        if (!tools.length) return '';
        if (intents.mail && tools.some(function (t) { return t.tab === 'bl'; })) {
            return 'Checking whether mail from ' + (entities.domain || subject) + ' looks legitimate: sender authentication, then a blacklist check.';
        }
        if (intents.mail || (tools.length === 1 && tools[0].tab === 'emailcheck')) return 'Checking mail authentication for ' + (entities.email || entities.domain) + ' — MX, SPF, DKIM and DMARC.';
        if (intents.blacklist && !intents.location) return 'Checking whether ' + (entities.ip || entities.domain) + ' is listed on spam blacklists.';
        if (intents.whois && tools.length === 1) return 'Looking up who owns ' + (entities.domain || entities.cidr || entities.ip) + '.';
        if (intents.location && tools.length === 1) return 'Looking up where ' + (entities.ip || entities.domain) + ' is.';
        if (intents.dns && tools.length === 1) return 'Looking up DNS records for ' + entities.domain + '.';
        if (intents.url && tools.length === 1) return 'Checking whether ' + (entities.url || entities.domain) + ' looks like a risky link.';
        if (tools.length === 1 && tools[0].tab === 'urlcheck') return 'Checking whether ' + (entities.url || entities.domain) + ' looks like a risky link.';
        if (intents.asn && entities.asn && tools.length === 1) return 'Looking up who operates ' + entities.asn + '.';
        if (tools.length === 1 && tools[0].tab === 'asn') return 'Looking up who operates ' + entities.asn + '.';
        if (intents.asn && tools.length === 1) return 'Looking up the network that operates ' + (entities.ip || entities.domain) + '.';
        if (intents.tools && tools.length === 1) return 'Running ping, ports and traceroute for ' + (entities.ip || entities.domain) + '.';
        if (tools.length === 1 && tools[0].tab === 'ip') return 'Looking up ' + tools[0].value + '.';
        var names = tools.map(function (t) { return t.label.toLowerCase(); });
        return 'Checking ' + subject + ' with ' + names.join(' and ') + '.';
    }

    function planAsk(question) {
        var text = String(question || '').replace(/\s+/g, ' ').trim();
        var entities = extractEntities(text);
        var intents = intentsOf(text);
        var domain = entities.domain;
        var ip = entities.ip;
        var tools = [];

        if (intents.myip && !ip && !domain && !entities.asn && !entities.url && !entities.email) {
            addTool(tools, 'myip', 'self', 'What is my IP');
        } else {
            // An email address plus "legit/safe" is a mail question even if the word "email" is absent.
            if (entities.email && intents.safe) intents.mail = true;
            var explicit = intents.mail || intents.blacklist || intents.whois || intents.asn || intents.location || intents.dns || intents.url || intents.tools;
            if (intents.mail) addTool(tools, 'emailcheck', entities.email || domain, 'Sender check');
            if (intents.blacklist || (intents.mail && intents.safe)) {
                addTool(tools, 'bl', ip || domain, 'Blacklist');
            }
            if (intents.whois) addTool(tools, 'whois', entities.cidr || domain || ip, 'WHOIS');
            if (intents.dns && domain) addTool(tools, 'dns', domain, 'DNS lookup');
            if (intents.url) addTool(tools, 'urlcheck', entities.url || (domain ? ('https://' + domain) : ''), 'URL check');
            if (intents.asn) {
                if (entities.asn) addTool(tools, 'asn', entities.asn, 'ASN lookup');
                else addTool(tools, 'ip', ip || domain, 'IP lookup');
            }
            if (intents.location) addTool(tools, 'ip', ip || domain, 'IP lookup');
            if (intents.tools) addTool(tools, 'tools', ip || domain, 'Net tools');
            if (!explicit) {
                if (entities.url && !domain) addTool(tools, 'urlcheck', entities.url, 'URL check');
                else if (entities.url && !intents.url) addTool(tools, 'urlcheck', entities.url, 'URL check');
                else if (entities.email) addTool(tools, 'emailcheck', entities.email, 'Sender check');
                else if (entities.cidr) addTool(tools, 'whois', entities.cidr, 'WHOIS');
                else if (entities.asn) addTool(tools, 'asn', entities.asn, 'ASN lookup');
                else if (ip) addTool(tools, 'ip', ip, 'IP lookup');
                else if (domain) addTool(tools, 'ip', domain, 'IP lookup');
            }
        }

        // A URL pasted with no other intent should be a URL check, not an IP lookup of the host.
        if (!intents.location && !intents.blacklist && !intents.whois && !intents.dns && !intents.mail && !intents.asn && !intents.tools && entities.url) {
            tools = tools.filter(function (t) { return t.tab === 'urlcheck'; });
            if (!tools.length) addTool(tools, 'urlcheck', entities.url, 'URL check');
        }

        var suggestions = [
            'Is mail from example.com safe?',
            'Where is 8.8.8.8?',
            'Who owns cloudflare.com?',
            'Is 1.1.1.1 blacklisted?',
            'Show DNS records for ignix.co.uk',
            'What is my IP?'
        ];

        return {
            query: text,
            entities: entities,
            intents: intents,
            tools: tools,
            summary: summaryFor(intents, entities, tools),
            suggestions: suggestions,
            matched: tools.length > 0
        };
    }

    var api = { planAsk: planAsk, extractEntities: extractEntities, intentsOf: intentsOf };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.ignixAsk = api;
})(typeof window !== 'undefined' ? window : globalThis);
