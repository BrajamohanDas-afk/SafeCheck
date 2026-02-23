"use i18n";

import { motion } from "framer-motion";
import { Upload, Link2, Gauge, CheckCircle, ArrowDown } from "lucide-react";

const HowItWorks = () => {
  return (
    <section className="py-24 relative" id="how-it-works">
      <div className="container px-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <h2 className="font-display text-4xl md:text-5xl font-bold mb-4">
            How SafeCheck works
          </h2>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
            A practical workflow for download safety: source check, file scan, smart scoring, then action.
          </p>
        </motion.div>

        <div className="max-w-4xl mx-auto">
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0, duration: 0.5 }}
            className="relative"
          >
            <div className="flex gap-6 md:gap-10 items-start mb-12">
              <div className="relative flex flex-col items-center">
                <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                  <Link2 className="w-7 h-7 text-primary" />
                </div>
                <div className="absolute top-20 w-px h-16 bg-gradient-to-b from-primary/50 to-transparent" />
              </div>
              <div className="flex-1 pt-2">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-sm font-semibold text-primary">Step 1</span>
                </div>
                <h3 className="font-display text-2xl font-semibold mb-3">Check the source URL first</h3>
                <p className="text-muted-foreground leading-relaxed max-w-lg">
                  Run source reputation checks before downloading. SafeCheck combines trust DB data, threat intel hits, and report history.
                </p>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.2, duration: 0.5 }}
            className="relative"
          >
            <div className="flex gap-6 md:gap-10 items-start mb-12">
              <div className="relative flex flex-col items-center">
                <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                  <Upload className="w-7 h-7 text-primary" />
                </div>
                <div className="absolute top-20 w-px h-16 bg-gradient-to-b from-primary/50 to-transparent" />
              </div>
              <div className="flex-1 pt-2">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-sm font-semibold text-primary">Step 2</span>
                </div>
                <h3 className="font-display text-2xl font-semibold mb-3">Scan + hash any file type</h3>
                <p className="text-muted-foreground leading-relaxed max-w-lg">
                  Upload any file up to 32MB. SafeCheck computes SHA-256, checks cache first, then requests a full VirusTotal analysis if needed.
                </p>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.4, duration: 0.5 }}
            className="relative"
          >
            <div className="flex gap-6 md:gap-10 items-start mb-12">
              <div className="relative flex flex-col items-center">
                <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                  <Gauge className="w-7 h-7 text-primary" />
                </div>
                <div className="absolute top-20 w-px h-16 bg-gradient-to-b from-primary/50 to-transparent" />
              </div>
              <div className="flex-1 pt-2">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-sm font-semibold text-primary">Step 3</span>
                </div>
                <h3 className="font-display text-2xl font-semibold mb-3">Get a smart risk score</h3>
                <p className="text-muted-foreground leading-relaxed max-w-lg">
                  See a 0-100 risk score with transparent reasons: threat intel matches, TLS/redirect behavior, and metadata anomalies.
                </p>
              </div>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.6, duration: 0.5 }}
            className="relative"
          >
            <div className="flex gap-6 md:gap-10 items-start mb-12">
              <div className="relative flex flex-col items-center">
                <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                  <CheckCircle className="w-7 h-7 text-primary" />
                </div>
              </div>
              <div className="flex-1 pt-2">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-sm font-semibold text-primary">Step 4</span>
                </div>
                <h3 className="font-display text-2xl font-semibold mb-3">Take action with confidence</h3>
                <p className="text-muted-foreground leading-relaxed max-w-lg">
                  Use verdict + score + reasons to decide: proceed, verify further, or block. Submit source reports and let auto-moderation improve trust data.
                </p>
              </div>
            </div>
          </motion.div>
        </div>

        {/* Bottom CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.6, duration: 0.5 }}
          className="text-center mt-12"
        >
          <div className="inline-flex items-center gap-2 text-muted-foreground">
            <span>Designed for fast decisions, not blind trust</span>
            <ArrowDown className="w-4 h-4 animate-bounce" />
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default HowItWorks;
