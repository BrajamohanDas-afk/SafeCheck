import { useState } from "react";
import { motion } from "framer-motion";
import { Shield, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import FileChecker from "@/features/file-safety/ui/FileChecker";
import heroBg from "@/assets/hero-bg.jpg";

const Hero = () => {
  const [isFileCheckerOpen, setIsFileCheckerOpen] = useState(false);

  return (
    <>
      <FileChecker isOpen={isFileCheckerOpen} onClose={() => setIsFileCheckerOpen(false)} />
      <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background image with overlay */}
      <div 
        className="absolute inset-0 z-0"
        style={{
          backgroundImage: `url(${heroBg.src})`,
          backgroundSize: "cover",
          backgroundPosition: "center",
        }}
      >
        <div className="absolute inset-0 bg-background/85" />
        <div className="absolute inset-0 bg-grid opacity-30" />
      </div>
      
      {/* Glow effect */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[800px] h-[600px] opacity-30 pointer-events-none">
        <div className="w-full h-full rounded-full bg-primary/20 blur-[120px]" />
      </div>

      <div className="container relative z-10 px-4 py-20">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="max-w-4xl mx-auto text-center"
        >
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-primary/30 bg-primary/10 mb-8"
          >
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">File Safety & Integrity Checker</span>
          </motion.div>

          {/* Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.6 }}
            className="font-display text-5xl md:text-7xl font-bold mb-6 leading-tight"
          >
            Verify Downloaded Files{" "}
            <span className="text-gradient">Before You Run Them</span>
          </motion.h1>

          {/* Subheadline */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.6 }}
            className="text-lg md:text-xl text-muted-foreground mb-10 max-w-2xl mx-auto leading-relaxed"
          >
            A security tool for executables downloaded from untrusted sources.
            Run scan, hash, and torrent checks before installation. Get a clear verdict in seconds:
            <span className="text-safe font-medium"> Safe</span>, 
            <span className="text-suspicious font-medium"> Suspicious</span>, or 
            <span className="text-dangerous font-medium"> Dangerous</span>.
          </motion.p>

          {/* CTA Buttons */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5, duration: 0.6 }}
            className="flex flex-col sm:flex-row gap-4 justify-center items-center"
          >
            <Button 
              size="lg" 
              className="glow-primary text-lg px-8 py-6 font-semibold"
              onClick={() => setIsFileCheckerOpen(true)}
            >
              Check a File Now
              <ArrowRight className="w-5 h-5 ml-2" />
            </Button>
            <Button variant="outline" size="lg" className="text-lg px-8 py-6">
              Learn How It Works
            </Button>
          </motion.div>

          {/* Trust indicators */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.7, duration: 0.6 }}
            className="mt-16 flex flex-wrap justify-center gap-8 text-muted-foreground text-sm"
          >
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-safe" />
              <span>Zero installation required</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-primary" />
              <span>70+ antivirus engines</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-accent" />
              <span>Results in seconds</span>
            </div>
          </motion.div>
        </motion.div>

        {/* Verdict Demo Cards */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8, duration: 0.8 }}
          className="mt-20 max-w-5xl mx-auto"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <VerdictCard 
              verdict="safe"
              title="Safe"
              description="No threats detected. File passed all security checks."
            />
            <VerdictCard 
              verdict="suspicious"
              title="Suspicious"
              description="Some flags detected. Exercise caution before running."
            />
            <VerdictCard 
              verdict="dangerous"
              title="Dangerous"
              description="Multiple threats detected. Do not run this file."
            />
          </div>
        </motion.div>
      </div>
    </section>
    </>
  );
};

interface VerdictCardProps {
  verdict: "safe" | "suspicious" | "dangerous";
  title: string;
  description: string;
}

const VerdictCard = ({ verdict, title, description }: VerdictCardProps) => {
  const verdictStyles = {
    safe: "border-safe/30 bg-safe-muted/50",
    suspicious: "border-suspicious/30 bg-suspicious-muted/50",
    dangerous: "border-dangerous/30 bg-dangerous-muted/50",
  };

  const iconStyles = {
    safe: "bg-safe text-safe-foreground",
    suspicious: "bg-suspicious text-suspicious-foreground",
    dangerous: "bg-dangerous text-dangerous-foreground",
  };

  const pulseStyles = {
    safe: "pulse-safe",
    suspicious: "",
    dangerous: "pulse-dangerous",
  };

  return (
    <motion.div
      whileHover={{ scale: 1.02, y: -4 }}
      className={`glass-card p-6 ${verdictStyles[verdict]} transition-all duration-300`}
    >
      <div className="flex items-start gap-4">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${iconStyles[verdict]} ${pulseStyles[verdict]}`}>
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <h3 className={`font-display font-semibold text-lg text-${verdict}`}>{title}</h3>
          <p className="text-muted-foreground text-sm mt-1">{description}</p>
        </div>
      </div>
    </motion.div>
  );
};

export default Hero;
