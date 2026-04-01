import { Link } from 'react-router-dom';
import { ShieldIcon } from '../components/Icons.tsx';

export default function Privacy() {
  return (
    <div className="min-h-screen bg-slate-950">
      <header className="border-b border-slate-800/50 py-4 px-6">
        <div className="max-w-4xl mx-auto flex items-center gap-2.5">
          <Link to="/" className="flex items-center gap-2.5 hover:opacity-80 transition-opacity">
            <div className="w-8 h-8 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
              <ShieldIcon className="w-4 h-4 text-brand-400" />
            </div>
            <span className="text-sm font-bold text-slate-300">WPSentry</span>
          </Link>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-16">
        <h1 className="text-3xl font-bold text-slate-100 mb-2">Privacy Policy</h1>
        <p className="text-sm text-slate-500 mb-12">Last updated: April 1, 2026</p>

        <div className="prose-dark space-y-8 text-sm text-slate-300 leading-relaxed">
          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">1. Data We Collect</h2>
            <p className="text-slate-400">We collect the following information when you use WPSentry:</p>
            <ul className="list-disc list-inside space-y-1.5 mt-2 text-slate-400">
              <li><strong className="text-slate-300">Account information:</strong> Email address and password hash (securely hashed using PBKDF2-SHA256).</li>
              <li><strong className="text-slate-300">Scan targets:</strong> URLs of WordPress websites you submit for scanning.</li>
              <li><strong className="text-slate-300">Scan results:</strong> Security findings, vulnerability reports, and module execution data generated during scans.</li>
              <li><strong className="text-slate-300">Usage data:</strong> Scan frequency, feature usage, timestamps, and rate limit counters.</li>
              <li><strong className="text-slate-300">Scanned site data:</strong> When scanning a target website, our scanner may encounter and record data publicly accessible on that site, including but not limited to: WordPress version numbers, installed plugin/theme names, publicly accessible usernames (via WordPress REST API or URL-based enumeration), server configuration headers, and security vulnerability indicators. This data is stored as part of your scan report and is visible only to you.</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">2. Legal Basis for Processing (GDPR)</h2>
            <p className="text-slate-400">We process personal data under the following legal bases (GDPR Article 6):</p>
            <ul className="list-disc list-inside space-y-1.5 mt-2 text-slate-400">
              <li><strong className="text-slate-300">Account data:</strong> Contract performance (Art. 6(1)(b)) — necessary to provide the Service you requested.</li>
              <li><strong className="text-slate-300">Scan results and usage data:</strong> Legitimate interest (Art. 6(1)(f)) — enabling authorized security testing of websites you administer.</li>
              <li><strong className="text-slate-300">Publicly-accessible usernames discovered during scans:</strong> Legitimate interest (Art. 6(1)(f)) — we have conducted a balancing test and determined that the interest of authorized website administrators in identifying security vulnerabilities outweighs the minimal privacy impact of processing usernames that are already publicly exposed on those websites.</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">3. How We Use Your Data</h2>
            <p className="text-slate-400">Your data is used to:</p>
            <ul className="list-disc list-inside space-y-1.5 mt-2 text-slate-400">
              <li>Provide and operate the security scanning service.</li>
              <li>Authenticate your identity and manage your account.</li>
              <li>Enforce usage limits and prevent abuse.</li>
              <li>Improve scanning accuracy and detection capabilities.</li>
              <li>Generate security reports for your review.</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">4. Data Storage</h2>
            <p className="text-slate-400">
              All data is stored on Cloudflare's global infrastructure:
            </p>
            <ul className="list-disc list-inside space-y-1.5 mt-2 text-slate-400">
              <li><strong className="text-slate-300">D1 (SQLite):</strong> Account information, scan metadata, usage records, and API keys.</li>
              <li><strong className="text-slate-300">R2 (Object Storage):</strong> Full scan report data including detailed findings.</li>
              <li><strong className="text-slate-300">KV (Key-Value):</strong> Session tokens and rate limit counters.</li>
            </ul>
            <p className="mt-3 text-slate-400">
              Data is encrypted in transit using TLS and stored within Cloudflare's secure infrastructure. Passwords are never stored in plaintext — only cryptographic hashes using PBKDF2-SHA256 with 100,000 iterations and per-user random salts.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">5. International Data Transfers</h2>
            <p className="text-slate-400">
              WPSentry uses Cloudflare, Inc. (United States) for all infrastructure. Data may be processed
              in countries outside the European Economic Area. Cloudflare processes data under Standard
              Contractual Clauses (SCCs) approved by the European Commission and participates in the EU-US
              Data Privacy Framework. Cloudflare's Data Processing Addendum is available at{' '}
              <a href="https://www.cloudflare.com/cloudflare-customer-dpa/" target="_blank" rel="noopener noreferrer"
                 className="text-brand-400 hover:text-brand-300 transition-colors">
                cloudflare.com/cloudflare-customer-dpa
              </a>.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">6. Third Parties</h2>
            <p className="text-slate-400">
              We use <strong className="text-slate-300">Cloudflare, Inc.</strong> as our sole infrastructure provider for hosting, data storage, and content delivery. No scan data or personal information is sold or shared with any other third parties. Cloudflare processes data in accordance with their{' '}
              <a href="https://www.cloudflare.com/privacypolicy/" target="_blank" rel="noopener noreferrer" className="text-brand-400 hover:text-brand-300 transition-colors">
                Privacy Policy
              </a>.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">7. Data Retention</h2>
            <p className="text-slate-400">
              <strong className="text-slate-300">Scan Data Retention:</strong> Scan results and associated reports are retained for 90 days from the date of the scan. After 90 days, scan data is automatically deleted. Account information is retained until you delete your account. You may delete individual scan results at any time from the Scan History page.
            </p>
            <p className="mt-3 text-slate-400">
              Upon account deletion, all associated data — including scan history, reports stored in R2, usage records, and API keys — is permanently deleted. Session tokens expire automatically after 24 hours.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">8. Your Rights (GDPR / CCPA)</h2>
            <p className="text-slate-400">You have the right to:</p>
            <ul className="list-disc list-inside space-y-1.5 mt-2 text-slate-400">
              <li><strong className="text-slate-300">Access:</strong> Request a copy of all data associated with your account.</li>
              <li><strong className="text-slate-300">Deletion:</strong> Delete your account and all associated data at any time through the Settings page.</li>
              <li><strong className="text-slate-300">Portability:</strong> Export your scan data in JSON, PDF, or CSV formats.</li>
            </ul>
            <p className="mt-3 text-slate-400">
              <strong className="text-slate-300">European Union Users (GDPR):</strong> If you are located in the EU/EEA, you have the right to: access your personal data, correct inaccurate data, delete your data ("right to be forgotten"), restrict processing, and data portability. To exercise these rights, contact us at{' '}
              <a href="mailto:support@wpsentry.link" className="text-brand-400 hover:text-brand-300 transition-colors">support@wpsentry.link</a>. Our lawful basis for processing is legitimate interest (providing the requested security scanning service).
            </p>
            <p className="mt-3 text-slate-400">
              <strong className="text-slate-300">California Users (CCPA):</strong> California residents may request information about personal data we collect, request deletion, and opt out of sale of personal data. We do not sell your personal data.
            </p>
            <p className="mt-3 text-slate-400">
              To exercise any of these rights, you may use the in-app features or contact us at{' '}
              <a href="mailto:support@wpsentry.link" className="text-brand-400 hover:text-brand-300 transition-colors">
                support@wpsentry.link
              </a>.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">9. Cookies</h2>
            <p className="text-slate-400">
              WPSentry uses a single essential cookie:
            </p>
            <div className="mt-3 bg-slate-900/60 border border-slate-800 rounded-xl p-4">
              <div className="flex items-start gap-4">
                <div>
                  <p className="text-slate-200 font-medium font-mono text-xs">jwp_session</p>
                  <p className="text-slate-500 text-xs mt-1">Authentication session token. HttpOnly, Secure. Expires after 24 hours.</p>
                  <p className="text-slate-600 text-xs mt-0.5">Type: Essential — required for the Service to function.</p>
                </div>
              </div>
            </div>
            <p className="mt-3 text-slate-400">
              We do not use any analytics, advertising, or tracking cookies.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">10. EU Digital Services Act</h2>
            <p className="text-slate-400">
              <strong className="text-slate-300">EU Digital Services Act:</strong> WPSentry is a security analysis tool. All automated scanning is performed solely at the request of the registered account holder. We do not use scan data for advertising, profiling unrelated to service delivery, or any purpose beyond providing the security scanning service you requested.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">11. robots.txt and Scanning Disclosure</h2>
            <p className="text-slate-400">
              WPSentry fetches the <code className="text-slate-300 bg-slate-800 px-1 rounded">robots.txt</code> file from target websites as part of its security assessment. While the scanner reviews <code className="text-slate-300 bg-slate-800 px-1 rounded">robots.txt</code> contents, it focuses on security-relevant paths and does not fully honor Disallow rules during a security assessment — since the goal is to identify vulnerabilities that an attacker could exploit regardless of those rules. This behavior is disclosed here in the interest of transparency.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">12. Changes to This Policy</h2>
            <p className="text-slate-400">
              We may update this Privacy Policy from time to time. Changes will be posted on this page with an updated effective date. We encourage you to review this page periodically.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">13. Rights of Third Parties (Scanned Sites)</h2>
            <p className="text-slate-400">
              If your username, configuration data, or other information appears in a scan result generated
              from your website, you have the right to request its deletion. Contact{' '}
              <a href="mailto:abuse@wpsentry.link" className="text-brand-400 hover:text-brand-300 transition-colors">
                abuse@wpsentry.link
              </a>
              {' '}with your request. We will process it within 30 days in accordance with GDPR Article 17
              (right to erasure). You may also report unauthorized scanning of your website to this address.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">14. Contact</h2>
            <p className="text-slate-400">
              If you have any questions about this Privacy Policy or our data practices, please contact us at{' '}
              <a href="mailto:support@wpsentry.link" className="text-brand-400 hover:text-brand-300 transition-colors">
                support@wpsentry.link
              </a>.
            </p>
          </section>
        </div>
      </main>

      <footer className="border-t border-slate-800/50 py-8">
        <div className="max-w-4xl mx-auto px-6 flex items-center justify-between text-xs text-slate-600">
          <span>&copy; {new Date().getFullYear()} WPSentry</span>
          <div className="flex items-center gap-4">
            <Link to="/terms" className="hover:text-slate-400 transition-colors">Terms</Link>
            <Link to="/privacy" className="hover:text-slate-400 transition-colors">Privacy</Link>
            <Link to="/report-abuse" className="hover:text-slate-400 transition-colors">Report Abuse</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
