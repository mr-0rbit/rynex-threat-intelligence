import { useState, type FormEvent } from "react";

export function Footer() {
  const [email, setEmail] = useState("");
  const [subscribed, setSubscribed] = useState(false);

  const handleSubscribe = (e: FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) return;
    setSubscribed(true);
  };

  return (
    <footer className="relative mt-auto w-full overflow-hidden border-t border-ink-700/80 bg-ink-950 px-4 sm:px-8 pt-12 pb-8 font-sans text-ink-300">
      {/* Subtle top cyan ambient glow */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_0%,rgba(0,212,255,0.06),transparent_70%)]"
      />

      {/* Main Container */}
      <div className="relative z-10 mx-auto max-w-7xl rounded-xl border border-ink-700/90 bg-ink-900/95 p-6 sm:p-8 shadow-2xl backdrop-blur-xl overflow-hidden">
        {/* Subtle accent blur corner highlights */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -top-24 -left-20 h-64 w-80 rounded-full bg-accent/5 blur-3xl"
        />
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -bottom-24 -right-20 h-64 w-80 rounded-full bg-accent/5 blur-3xl"
        />

        {/* Top Section: Brand + Navigation Grid */}
        <div className="relative z-10 grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-10 items-start">
          {/* Brand & Newsletter Column */}
          <div className="lg:col-span-5 max-w-lg">
            <div className="flex items-center gap-3 mb-4">
              <div className="flex h-9 w-9 items-center justify-center rounded border border-ink-600 bg-ink-950 p-1.5 shadow-[0_0_12px_rgba(0,212,255,0.15)] ring-1 ring-accent/20">
                <img
                  src="/logo.png"
                  alt="Rynex Technologies"
                  className="h-full w-full object-contain drop-shadow-[0_0_6px_rgba(0,212,255,0.4)]"
                />
              </div>
              <span className="text-sm font-bold tracking-[0.08em] text-white font-mono">
                Rynex Technologies
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-mono leading-snug mb-4">
              Detect, Exploit &amp; Secure.
              <br />
              <span className="text-accent drop-shadow-[0_0_12px_rgba(0,212,255,0.35)]">
                Enterprise Cyber Defense.
              </span>
            </h2>

            {/* Newsletter */}
            {subscribed ? (
              <div className="flex items-center gap-2 rounded border border-accent/40 bg-accent/10 px-3.5 py-2 text-xs font-mono text-accent">
                <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
                <span>Thank you. Security advisory dispatch confirmed.</span>
              </div>
            ) : (
              <form onSubmit={handleSubscribe} className="relative flex w-full max-w-md items-center rounded border border-ink-600 bg-ink-950 p-1 shadow-inner focus-within:border-accent focus-within:ring-1 focus-within:ring-accent/40 transition-colors">
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="security@enterprise.com"
                  aria-label="Work Email Address"
                  className="flex-1 bg-transparent px-3 py-1.5 text-xs text-ink-100 placeholder:text-ink-500 font-mono focus:outline-none min-w-0"
                />
                <button
                  type="submit"
                  className="rounded bg-accent px-4 py-1.5 text-xs font-mono font-bold uppercase tracking-wider text-black transition-all hover:bg-white hover:shadow-[0_0_12px_rgba(0,212,255,0.4)] shrink-0"
                >
                  Subscribe
                </button>
              </form>
            )}
            <p className="mt-2.5 text-[11px] text-ink-400 font-mono leading-relaxed">
              Security briefs &amp; zero-day advisories. Unsubscribe anytime.
            </p>
          </div>

          {/* Navigation Links Column */}
          <div className="lg:col-span-7 rounded-lg border border-ink-700/80 bg-ink-850/80 p-5 sm:p-6 backdrop-blur-md">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-6">
              {/* Column 1: Services */}
              <div>
                <h3 className="mb-3 text-2xs font-bold uppercase tracking-[0.14em] text-accent font-mono">
                  Services
                </h3>
                <ul className="space-y-2 text-xs font-mono">
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/services/vapt"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      VAPT &amp; Red Team
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/services/soc"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      24/7 SOC Operations
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/services/grc"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      GRC &amp; Audits
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/services/cloud"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Cloud Architecture
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/services"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Service Directory
                    </a>
                  </li>
                </ul>
              </div>

              {/* Column 2: Company */}
              <div>
                <h3 className="mb-3 text-2xs font-bold uppercase tracking-[0.14em] text-accent font-mono">
                  Company
                </h3>
                <ul className="space-y-2 text-xs font-mono">
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/about"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      About Us
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/careers"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      <span>Careers</span>
                      <span className="rounded bg-accent/20 border border-accent/40 text-accent font-mono px-1 py-0.2 text-[8px] font-bold tracking-wider">
                        HIRING
                      </span>
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/internship"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Internship Program
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/contact"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Contact Desk
                    </a>
                  </li>
                </ul>
              </div>

              {/* Column 3: Resources */}
              <div>
                <h3 className="mb-3 text-2xs font-bold uppercase tracking-[0.14em] text-accent font-mono">
                  Resources
                </h3>
                <ul className="space-y-2 text-xs font-mono">
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/blog"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Threat Intelligence
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/events"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Events &amp; CTF
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/policies#section-04"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Vulnerability Disclosure
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/portal/login"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Client Portal
                    </a>
                  </li>
                </ul>
              </div>

              {/* Column 4: Legal & Trust */}
              <div>
                <h3 className="mb-3 text-2xs font-bold uppercase tracking-[0.14em] text-accent font-mono">
                  Legal &amp; Trust
                </h3>
                <ul className="space-y-2 text-xs font-mono">
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/policies"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Privacy &amp; Governance
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/policies#section-06"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Information We Collect
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/policies#section-08"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Cookie &amp; Tracking
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/policies#section-10"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Data Deletion Rights
                    </a>
                  </li>
                  <li>
                    <a
                      href="https://www.rynexsecurity.com/policies#section-03"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block text-ink-300 hover:text-white hover:translate-x-1 transition-all"
                    >
                      Rules of Engagement
                    </a>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Bar: Copyright, Status, Social Links */}
        <div className="relative z-10 mt-8 pt-5 border-t border-ink-700/80 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono">
          <div className="flex flex-wrap items-center gap-3 text-xs text-ink-400">
            <span>© 2026 Rynex Technologies. All Rights Reserved.</span>
            <span className="inline-flex items-center gap-2 rounded border border-accent/30 bg-accent/10 px-2.5 py-1 text-2xs text-ink-200">
              <span className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_8px_#00d4ff] animate-pulse" />
              <span>All systems operational</span>
            </span>
          </div>

          {/* Social Links */}
          <div className="flex items-center gap-1.5 rounded border border-ink-700/80 bg-ink-950 px-2.5 py-1">
            {/* Discord */}
            <a
              href="https://discord.gg/V8CYUKCSKJ"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Discord"
              className="flex h-7 w-7 items-center justify-center rounded text-ink-400 hover:text-accent hover:bg-ink-800 transition-colors"
            >
              <svg className="h-3.5 w-3.5 fill-current" viewBox="0 0 24 24">
                <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.929 1.793 8.18 1.793 12.061 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.894.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
              </svg>
            </a>

            {/* LinkedIn */}
            <a
              href="https://www.linkedin.com/company/rynex.techs"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="LinkedIn"
              className="flex h-7 w-7 items-center justify-center rounded text-ink-400 hover:text-accent hover:bg-ink-800 transition-colors"
            >
              <svg className="h-3.5 w-3.5 fill-current" viewBox="0 0 24 24">
                <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.28 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.75M6.46 8.76a1.67 1.67 0 1 0 0-3.34 1.67 1.67 0 0 0 0 3.34M7.86 18.5V10.1H5.06v8.4h2.8z" />
              </svg>
            </a>

            {/* Instagram */}
            <a
              href="https://www.instagram.com/rynex.techs"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Instagram"
              className="flex h-7 w-7 items-center justify-center rounded text-ink-400 hover:text-accent hover:bg-ink-800 transition-colors"
            >
              <svg className="h-3.5 w-3.5 fill-current" viewBox="0 0 24 24">
                <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838a6.162 6.162 0 1 0 0 12.324 6.162 6.162 0 0 0 0-12.324zM12 16a4 4 0 1 1 0-8 4 4 0 0 1 0 8zm6.406-11.845a1.44 1.44 0 1 0 0 2.881 1.44 1.44 0 0 0 0-2.881z" />
              </svg>
            </a>

            {/* X / Twitter */}
            <a
              href="https://x.com/rynex.techs"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="X"
              className="flex h-7 w-7 items-center justify-center rounded text-ink-400 hover:text-accent hover:bg-ink-800 transition-colors"
            >
              <svg className="h-3 w-3 fill-current" viewBox="0 0 24 24">
                <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
              </svg>
            </a>

            {/* GitHub */}
            <a
              href="https://github.com/rynexsecurity"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="GitHub"
              className="flex h-7 w-7 items-center justify-center rounded text-ink-400 hover:text-accent hover:bg-ink-800 transition-colors"
            >
              <svg className="h-3.5 w-3.5 fill-current" viewBox="0 0 24 24">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0 0 22 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
            </a>
          </div>
        </div>

        {/* Large Background Watermark */}
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -bottom-10 left-4 text-white/[0.02] text-[clamp(70px,16vw,200px)] font-black font-mono tracking-tighter select-none leading-none z-0"
        >
          RYNEX
        </div>
      </div>
    </footer>
  );
}
