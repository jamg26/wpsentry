import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

export default function CookieConsent() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (localStorage.getItem('cookie_consent') !== 'accepted') {
      setVisible(true);
    }
  }, []);

  if (!visible) return null;

  const handleAccept = () => {
    localStorage.setItem('cookie_consent', 'accepted');
    setVisible(false);
  };

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50 bg-slate-900 border-t border-slate-800 px-6 py-4 animate-fade-in">
      <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
        <p className="text-sm text-slate-400 text-center sm:text-left">
          We use essential cookies for authentication.
        </p>
        <div className="flex items-center gap-3 shrink-0">
          <Link
            to="/privacy"
            className="text-sm text-brand-400 hover:text-brand-300 transition-colors"
          >
            Learn More
          </Link>
          <button
            onClick={handleAccept}
            className="bg-brand-600 hover:bg-brand-500 text-white font-medium py-2 px-5 rounded-xl text-sm transition-all"
          >
            Accept
          </button>
        </div>
      </div>
    </div>
  );
}
