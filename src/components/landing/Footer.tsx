import { Shield, Github, Twitter } from "lucide-react";

const Footer = () => {
  return (
    <footer className="border-t border-border py-12">
      <div className="container px-4">
        <div className="flex flex-col md:flex-row justify-between items-center gap-6">
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <span className="font-display text-xl font-semibold">SafeCheck</span>
          </div>

          {/* Links */}
          <nav className="flex flex-wrap justify-center gap-6 text-sm text-muted-foreground">
            <a href="#features" className="hover:text-foreground transition-colors">Features</a>
            <a href="#how-it-works" className="hover:text-foreground transition-colors">How it Works</a>
            <a href="#" className="hover:text-foreground transition-colors">Privacy</a>
            <a href="#" className="hover:text-foreground transition-colors">Terms</a>
          </nav>

          {/* Social */}
          <div className="flex items-center gap-4">
            <a 
              href="#" 
              className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center hover:bg-muted-foreground/20 transition-colors"
              aria-label="GitHub"
            >
              <Github className="w-4 h-4" />
            </a>
            <a 
              href="#" 
              className="w-9 h-9 rounded-lg bg-muted flex items-center justify-center hover:bg-muted-foreground/20 transition-colors"
              aria-label="Twitter"
            >
              <Twitter className="w-4 h-4" />
            </a>
          </div>
        </div>

        <div className="mt-8 pt-8 border-t border-border text-center text-sm text-muted-foreground">
          <p>© 2026 SafeCheck. File Safety & Integrity Checker.</p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
