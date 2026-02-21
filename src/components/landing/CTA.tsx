import { motion } from "framer-motion";
import { Shield, ArrowRight, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";

const CTA = () => {
  const handleStartScanningFree = () => {
    const heroSection = document.getElementById("hero-section");
    if (!heroSection) return;

    heroSection.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <section className="py-24 relative overflow-hidden">
      {/* Background glow */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="w-[600px] h-[400px] bg-primary/10 rounded-full blur-[100px] opacity-50" />
      </div>

      <div className="container relative z-10 px-4">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="max-w-4xl mx-auto text-center"
        >
          <div className="glass-card p-12 md:p-16">
            <Shield className="w-16 h-16 text-primary mx-auto mb-6" />
            
            <h2 className="font-display text-4xl md:text-5xl font-bold mb-6">
              Ready to check your files?
            </h2>
            
            <p className="text-muted-foreground text-lg mb-10 max-w-2xl mx-auto">
              Get peace of mind in seconds. No signup required, no software to install. 
              Just drag, drop, and know if it's safe.
            </p>

            <Button
              size="lg"
              className="glow-primary text-lg px-10 py-6 font-semibold"
              onClick={handleStartScanningFree}
            >
              Start Scanning Free
              <ArrowRight className="w-5 h-5 ml-2" />
            </Button>

            {/* Disclaimer */}
            <motion.div
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.3, duration: 0.5 }}
              className="mt-10 flex items-start gap-3 text-left max-w-2xl mx-auto p-4 rounded-lg bg-muted/50 border border-border"
            >
              <AlertCircle className="w-5 h-5 text-muted-foreground shrink-0 mt-0.5" />
              <p className="text-sm text-muted-foreground">
                <strong className="text-foreground">Disclaimer:</strong> SafeCheck provides risk assessments based on available data. 
                It cannot guarantee a file is safe. Always exercise caution with downloaded files.
              </p>
            </motion.div>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default CTA;
