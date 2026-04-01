import { Link } from 'react-router-dom';
import { ShieldIcon } from '../components/Icons.tsx';

export default function Terms() {
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
        <h1 className="text-3xl font-bold text-slate-100 mb-2">Terms of Service</h1>
        <p className="text-sm text-slate-500 mb-12">Last updated: April 1, 2026</p>

        <div className="prose-dark space-y-8 text-sm text-slate-300 leading-relaxed">
          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">1. Service Description</h2>
            <p>
              WPSentry ("the Service") is a WordPress security scanning tool. The Service allows registered users to perform automated security assessments of WordPress websites by running a suite of security modules that detect vulnerabilities, misconfigurations, and potential threats.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">2. Acceptable Use</h2>
            <p>By using the Service, you agree to:</p>
            <ul className="list-disc list-inside space-y-1.5 mt-2 text-slate-400">
              <li>Only scan websites that you own or for which you have explicit, written authorization to test.</li>
              <li>Not use the Service to conduct unauthorized security testing, penetration testing, or any form of attack against systems you do not own or have permission to test.</li>
              <li>Not attempt to circumvent rate limits, usage quotas, or other technical restrictions.</li>
              <li>Not use the Service for any illegal purpose or in violation of any applicable laws or regulations.</li>
              <li>Not reverse-engineer, decompile, or disassemble any part of the Service.</li>
            </ul>
            <p className="mt-3 text-slate-400">
              Unauthorized scanning of third-party websites may violate computer fraud laws in your jurisdiction. You are solely responsible for ensuring you have proper authorization before initiating any scan.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">3. Account Responsibilities</h2>
            <p className="text-slate-400">
              You are responsible for maintaining the confidentiality of your account credentials and for all activity that occurs under your account. You agree to immediately notify us of any unauthorized use of your account. You must provide a valid email address and accurate information when creating your account.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">4. Service Provided "As-Is"</h2>
            <p className="text-slate-400">
              The Service is provided on an "as-is" and "as-available" basis without warranties of any kind, either express or implied, including but not limited to implied warranties of merchantability, fitness for a particular purpose, and non-infringement. We do not warrant that the Service will be uninterrupted, error-free, or that scan results will be complete or accurate.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">5. Limitation of Liability</h2>
            <p className="text-slate-400">
              To the maximum extent permitted by applicable law, WPSentry and its operators shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including but not limited to loss of data, loss of profits, or business interruption, arising out of or related to your use of or inability to use the Service, even if advised of the possibility of such damages.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">6. Account Termination</h2>
            <p className="text-slate-400">
              We reserve the right to suspend or terminate your account at any time, with or without notice, for conduct that we determine, in our sole discretion, violates these Terms, is harmful to other users, or is otherwise objectionable. You may delete your account at any time through the Settings page. Upon deletion, all associated data including scan history and reports will be permanently removed.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">7. Service Changes</h2>
            <p className="text-slate-400">
              Features, functionality, and availability may change without notice. The Service may contain bugs or errors and is provided "as-is" without any obligation to provide support, maintenance, updates, or modifications. Usage limits, features, and pricing are subject to change.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">8. Authorized Use Warranty</h2>
            <p className="text-slate-400">
              By initiating any scan, you expressly warrant and represent that: (1) you are the owner of the target website, or (2) you have obtained explicit, written authorization from the website owner to conduct security testing on that website. You acknowledge that unauthorized security scanning may violate the Computer Fraud and Abuse Act (United States), the Computer Misuse Act (United Kingdom), and similar computer crime laws in other jurisdictions. You are solely responsible for ensuring compliance with all applicable laws before using this Service.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">9. Prohibited Uses</h2>
            <p className="text-slate-400">You may NOT use the Service to:</p>
            <ul className="list-disc list-inside space-y-1.5 mt-2 text-slate-400">
              <li>Scan websites you do not own and have not received explicit written authorization to test.</li>
              <li>Build reconnaissance databases or "hit-lists" of vulnerable websites.</li>
              <li>Conduct competitive intelligence-gathering on third-party businesses.</li>
              <li>Harass, intimidate, or threaten website owners using scan data.</li>
              <li>Resell scan results without adding substantial independent value.</li>
              <li>Automate mass scanning of websites without prior written consent from each site owner.</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">10. Indemnification</h2>
            <p className="text-slate-400">
              You agree to defend, indemnify, and hold harmless WPSentry and its operators from and against any claims, damages, losses, costs, and expenses (including reasonable attorneys' fees) arising out of or relating to: (1) your use of the Service, (2) your violation of these Terms, (3) your scanning of websites without proper authorization, or (4) your violation of any applicable law or third-party right.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">11. Governing Law</h2>
            <p className="text-slate-400">
              These Terms shall be governed by and construed in accordance with applicable law. Any disputes
              arising under or related to these Terms or the Service shall be resolved through binding
              arbitration or, where arbitration is not permitted, in the courts of competent jurisdiction.
              Nothing in this clause limits your rights under mandatory consumer protection laws in your
              jurisdiction.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">12. Law Enforcement Cooperation</h2>
            <p className="text-slate-400">
              We cooperate with law enforcement agencies and legal processes. Scan records, user account
              information, authorization attestation logs (including IP addresses and timestamps), and related
              data may be disclosed in response to valid legal process including subpoenas, court orders, or
              warrants. If you are the owner of a website that has been scanned without your authorization,
              please contact{' '}
              <a href="mailto:abuse@wpsentry.link" className="text-brand-400 hover:text-brand-300 transition-colors">
                abuse@wpsentry.link
              </a>
              . We will investigate and take appropriate action including account suspension.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">13. Changes to Terms</h2>
            <p className="text-slate-400">
              We reserve the right to modify these Terms at any time. Changes will be posted on this page with an updated effective date. Your continued use of the Service after changes are posted constitutes your acceptance of the revised Terms.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-slate-100 mb-3">14. Contact</h2>
            <p className="text-slate-400">
              If you have any questions about these Terms, please contact us at{' '}
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
