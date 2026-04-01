import { Link } from 'react-router-dom';
import { ShieldIcon } from '../components/Icons.tsx';

export default function ReportAbuse() {
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
        <h1 className="text-3xl font-bold text-slate-100 mb-2">Report Unauthorized Scanning</h1>
        <p className="text-sm text-slate-500 mb-12">Last updated: April 1, 2026</p>

        <div className="prose-dark space-y-8 text-sm text-slate-300 leading-relaxed">
          <section>
            <p className="text-slate-400">
              WPSentry is a WordPress security tool used by website owners and administrators. All scans
              require users to actively certify they have authorization to scan the target. If your website
              was scanned without your permission, please report it below.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">How to Report</h2>
            <p className="text-slate-400">
              Send an email to{' '}
              <a
                href="mailto:abuse@wpsentry.link?subject=Unauthorized%20Scan%20Report"
                className="text-brand-400 hover:text-brand-300 transition-colors"
              >
                abuse@wpsentry.link
              </a>
              {' '}with the subject line <strong className="text-slate-300">"Unauthorized Scan Report"</strong>.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">What to Include</h2>
            <ul className="list-disc list-inside space-y-1.5 mt-2 text-slate-400">
              <li>The target URL of your website that was scanned.</li>
              <li>The approximate date and time of the scan (if known).</li>
              <li>Any evidence you have, such as server access logs showing unusual requests from our scanner's User-Agent (<code className="text-slate-300 bg-slate-800 px-1 rounded">WPSentry/3.0</code>).</li>
              <li>Your relationship to the website (owner, administrator, hosting provider, etc.).</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Our Response</h2>
            <p className="text-slate-400">
              We will investigate and respond within <strong className="text-slate-300">72 hours</strong>.
              Accounts found to have scanned sites without authorization will be suspended. We maintain
              authorization attestation logs (including IP addresses and timestamps) for all scans and will
              cooperate with law enforcement if required.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Data Removal Requests</h2>
            <p className="text-slate-400">
              If scan results contain data from your website (such as publicly-exposed usernames or
              configuration data) and you would like it removed, please include this in your report.
              We will process erasure requests within 30 days in accordance with GDPR Article 17.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">Security Researchers</h2>
            <p className="text-slate-400">
              If you are testing WPSentry's own infrastructure, see our Responsible Disclosure page
              (coming soon). Please do not use the abuse report form for vulnerability disclosures about
              WPSentry itself.
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
