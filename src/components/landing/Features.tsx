"use i18n";

import { motion } from "framer-motion";
import { Shield, FileSearch, Hash, AlertTriangle, FileArchive } from "lucide-react";

const Features = () => {
  return (
    <section className="py-24 relative overflow-hidden" id="features">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-background via-card/50 to-background" />
      
      <div className="container relative z-10 px-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-border bg-card mb-6">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-muted-foreground">Comprehensive Protection</span>
          </div>
          <h2 className="font-display text-4xl md:text-5xl font-bold mb-4">
            Everything you need to stay safe
          </h2>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
            Four layers of protection in one simple tool. No technical knowledge required.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-5xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0, duration: 0.5 }}
          >
            <div className="glass-card p-8 h-full hover:border-primary/50 transition-all duration-300 group">
              <div className="w-14 h-14 rounded-xl flex items-center justify-center bg-primary/10 mb-6 group-hover:scale-110 transition-transform duration-300">
                <FileArchive className="w-7 h-7 text-primary" />
              </div>
              <h3 className="font-display text-xl font-semibold mb-3">Torrent Metadata Analysis</h3>
              <p className="text-muted-foreground leading-relaxed">
                Preview file contents in Linux ISOs, open software distributions, and public domain media torrents.
              </p>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1, duration: 0.5 }}
          >
            <div className="glass-card p-8 h-full hover:border-primary/50 transition-all duration-300 group">
              <div className="w-14 h-14 rounded-xl flex items-center justify-center bg-accent/10 mb-6 group-hover:scale-110 transition-transform duration-300">
                <FileSearch className="w-7 h-7 text-accent" />
              </div>
              <h3 className="font-display text-xl font-semibold mb-3">Smart Scan Analysis</h3>
              <p className="text-muted-foreground leading-relaxed">
                Verify software downloaded from mirror links or unofficial sources with VirusTotal engine results.
              </p>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2, duration: 0.5 }}
          >
            <div className="glass-card p-8 h-full hover:border-primary/50 transition-all duration-300 group">
              <div className="w-14 h-14 rounded-xl flex items-center justify-center bg-safe/10 mb-6 group-hover:scale-110 transition-transform duration-300">
                <Hash className="w-7 h-7 text-safe" />
              </div>
              <h3 className="font-display text-xl font-semibold mb-3">Hash Verification</h3>
              <p className="text-muted-foreground leading-relaxed">
                Confirm cloud backups and downloaded installers were not corrupted or tampered with in transfer.
              </p>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.3, duration: 0.5 }}
          >
            <div className="glass-card p-8 h-full hover:border-primary/50 transition-all duration-300 group">
              <div className="w-14 h-14 rounded-xl flex items-center justify-center bg-suspicious/10 mb-6 group-hover:scale-110 transition-transform duration-300">
                <AlertTriangle className="w-7 h-7 text-suspicious" />
              </div>
              <h3 className="font-display text-xl font-semibold mb-3">Clear Verdicts</h3>
              <p className="text-muted-foreground leading-relaxed">
                Interpret complex antivirus outputs for non-technical users with a weighted Safe/Suspicious/Dangerous verdict.
              </p>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default Features;
