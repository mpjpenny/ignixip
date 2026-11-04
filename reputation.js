/* Shared reputation wording for the IP verdict, risk ring, and Ask summary.
   DNSBL answers are classified here so a public-resolver error is not a listing. */
(function (root) {
    var MAJOR = { 'Spamhaus ZEN': 1, 'Spamhaus SBL': 1, 'Spamhaus XBL': 1, 'Spamhaus ZEN IPv6': 1 };
    var MINOR = { 'Spamhaus PBL': 1, 'UCEPROTECT L1': 1, 'UCEPROTECT L2': 1 };

    function isKnownInfra(org, asn) {
        var blob = ((org || '') + ' ' + (asn || '')).toLowerCase();
        if (/google|cloudflare|amazon|aws\b|microsoft|azure|akamai|fastly|quad9|opendns|umbrella|facebook|meta platforms|apple inc|github|oracle cloud|digitalocean|linode|akamai|netflix|edgecast/.test(blob)) return true;
        var num = String(asn || '').toUpperCase().replace(/^AS/, '');
        return { 15169: 1, 13335: 1, 16509: 1, 14618: 1, 8075: 1, 32934: 1, 54113: 1, 20940: 1, 13238: 1, 714: 1, 36692: 1, 2906: 1 }[num] === 1;
    }

    function readDnsblResult(name, payload) {
        var codes = [];
        var answers = payload && payload.Answer ? payload.Answer : [];
        answers.forEach(function (a) {
            if (a && /^\d{1,3}(\.\d{1,3}){3}$/.test(a.data || '')) codes.push(a.data);
        });
        var error = false;
        var listed = false;
        codes.forEach(function (c) {
            var p = c.split('.').map(function (n) { return parseInt(n, 10); });
            if (p[0] === 127 && p[1] === 255 && p[2] === 255) error = true;
            else if (p[0] === 127 && p[3] >= 2 && p[3] <= 255) listed = true;
        });
        if (error && listed) error = false;
        var weight = 'none';
        if (listed) weight = MAJOR[name] ? 'major' : (MINOR[name] ? 'minor' : 'other');
        var status = (error && !listed) ? 'error' : (listed ? 'listed' : 'clean');
        return {
            name: name,
            listed: listed && !error,
            error: error && !listed,
            unavailable: !!(error && !listed),
            code: codes[0] || '',
            weight: listed && !error ? weight : 'none',
            status: status
        };
    }

    function names(list) {
        return list.map(function (r) { return r.name; });
    }

    function assessReputation(opts) {
        opts = opts || {};
        var results = opts.dnsblResults || [];
        var major = results.filter(function (r) { return r.listed && r.weight === 'major'; });
        var minor = results.filter(function (r) { return r.listed && r.weight === 'minor'; });
        var other = results.filter(function (r) { return r.listed && r.weight === 'other'; });
        var errors = results.filter(function (r) { return r.error || r.unavailable; });
        var spamhausDown = errors.some(function (r) { return /^Spamhaus/.test(r.name || ''); });
        var abuseScore = opts.abuseScore == null ? null : opts.abuseScore;
        var abuseReports = opts.abuseReports || 0;
        var known = isKnownInfra(opts.org, opts.asn);
        var total = results.length;
        var realListed = major.concat(minor).concat(other);

        var grade = 'clean';
        if (major.length || (abuseScore != null && abuseScore >= 50)) grade = 'serious';
        else if (other.length || (abuseScore != null && abuseScore >= 10)) grade = 'check';
        else if (minor.length) grade = 'note';

        if (known && grade === 'serious' && !(major.length && abuseScore != null && abuseScore >= 50)) grade = 'check';

        var listPhrase = names(major.concat(other).concat(minor)).join(', ');

        var listedText;
        if (!results.length) listedText = 'Blacklist check did not return.';
        else if (spamhausDown && !realListed.length) listedText = 'Spamhaus check unavailable. Other checked lists had no listing.';
        else if (spamhausDown) listedText = 'Spamhaus check unavailable. Listed on ' + listPhrase + '.';
        else if (!realListed.length) listedText = 'Not listed on ' + total + ' blacklists.';
        else listedText = 'Listed on ' + listPhrase + '.';
        if (abuseScore != null) {
            if (abuseScore === 0 && abuseReports > 0) listedText += ' AbuseIPDB confidence is 0%, across ' + abuseReports + ' older reports.';
            else if (!abuseReports) listedText += ' AbuseIPDB has no reports.';
            else listedText += ' AbuseIPDB confidence ' + abuseScore + '%.';
        }

        var means;
        if (opts.isTor && grade !== 'serious') {
            means = 'Worth checking. This is a Tor exit. The organisation above runs the exit, not the person who used it.';
            grade = grade === 'clean' || grade === 'note' ? 'check' : grade;
        } else if (grade === 'serious') {
            if (major.length) means = 'Serious reputation problem. Listed on ' + names(major).slice(0, 2).join(' and ') + ', so mail from it is likely to be refused.';
            else means = 'Serious reputation problem. AbuseIPDB confidence is ' + abuseScore + '%, which is high enough to treat recent reports as real.';
        } else if (grade === 'check' && known) {
            var hit = '';
            if (major.length) hit = 'Spamhaus reported ' + names(major).slice(0, 2).join(' and ') + '. ';
            else if (listPhrase) hit = 'Listed on ' + listPhrase + '. ';
            else if (abuseScore != null && abuseScore >= 10) hit = 'AbuseIPDB confidence is ' + abuseScore + '%. ';
            means = 'Worth checking, not an alarm. ' + hit + 'This is well-known shared infrastructure, so a hit here is often a false positive or a shared address.';
        } else if (grade === 'check') {
            var why = listPhrase ? ('Listed on ' + listPhrase + '.') : ('AbuseIPDB confidence is ' + abuseScore + '%.');
            means = 'Worth checking. ' + why + ' That can be a shared or temporary hit, not proof the whole network is hostile.';
        } else if (grade === 'note') {
            var minorOnlyPbl = minor.length && minor.every(function (r) { return r.name === 'Spamhaus PBL'; });
            if (minorOnlyPbl) means = 'Minor note. Listed on Spamhaus PBL, which is normal for many home and office connections and is not a sign of abuse.';
            else means = 'Minor note. Listed on ' + names(minor).join(', ') + ', which often covers a whole provider rather than this one address.';
        } else if (!results.length) {
            means = 'The organisation above owns the address. The blacklist check did not finish, so the record is incomplete.';
        } else if (known) {
            means = 'Clean record. Well-known infrastructure, with nothing on a major blacklist.';
        } else if (opts.isHosting) {
            means = 'Clean record. A hosting or cloud address with no major blacklist hit. Ordinary for a website, a CDN, or an API.';
        } else if (opts.isVpn) {
            means = 'Clean record. This looks like a VPN or proxy address. The organisation above runs the service, not necessarily the person at the keyboard.';
        } else {
            means = 'Clean record. A home or office connection with nothing that marks it as hostile.';
        }
        if (spamhausDown && !major.length && (grade === 'clean' || grade === 'note')) {
            means = realListed.length
                ? ('Spamhaus check unavailable. Listed on ' + listPhrase + '.')
                : 'Spamhaus check unavailable. Other lists that answered had no listing.';
            grade = 'unavailable';
        } else if (spamhausDown && !major.length) {
            means += ' Spamhaus check unavailable.';
        }

        var tone = grade === 'serious' ? 'bad' : ((grade === 'clean') ? 'clean' : 'watch');
        var listTone = (major.length || (abuseScore != null && abuseScore >= 50)) && !(known && !(abuseScore != null && abuseScore >= 50)) ? 'bad' : ((realListed.length || (abuseScore != null && abuseScore >= 10)) ? 'watch' : 'clean');
        if (known && listTone === 'bad') listTone = 'watch';
        if (grade === 'unavailable') listTone = 'watch';

        var owner = String(opts.owner || 'This network').replace(/\.+$/, '');
        return {
            owner: owner,
            meta: opts.meta || '',
            listed: listedText,
            means: means,
            tone: tone,
            listTone: listTone,
            recommendVpn: !!(opts.isVpn && !known && grade === 'clean'),
            grade: grade,
            askLine: owner + '. ' + means,
            major: major,
            minor: minor,
            other: other,
            errors: errors,
            knownInfra: known
        };
    }

    var api = { readDnsblResult: readDnsblResult, isKnownInfra: isKnownInfra, assessReputation: assessReputation, MAJOR: MAJOR, MINOR: MINOR };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.ignixReputation = api;
})(typeof window !== 'undefined' ? window : globalThis);
