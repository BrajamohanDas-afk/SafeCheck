import { useState } from "react";
import Navbar from "@/components/landing/Navbar";
import Hero from "@/components/landing/Hero";
import Features from "@/components/landing/Features";
import HowItWorks from "@/components/landing/HowItWorks";
import CTA from "@/components/landing/CTA";
import Footer from "@/components/landing/Footer";
import FileChecker from "@/features/file-safety/ui/FileChecker";

export default function LandingPage() {
  const [isFileCheckerOpen, setIsFileCheckerOpen] = useState(false);

  return (
    <div className="min-h-screen bg-background">
      <FileChecker isOpen={isFileCheckerOpen} onClose={() => setIsFileCheckerOpen(false)} />
      <Navbar onOpenFileChecker={() => setIsFileCheckerOpen(true)} />
      <Hero onOpenFileChecker={() => setIsFileCheckerOpen(true)} />
      <Features />
      <HowItWorks />
      <CTA />
      <Footer />
    </div>
  );
}
