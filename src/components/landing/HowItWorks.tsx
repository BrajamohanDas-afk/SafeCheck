import { motion } from "framer-motion";
import { Upload, FileArchive, CheckCircle, ArrowDown } from "lucide-react";

const steps = [
  {
    step: 1,
    icon: Upload,
    title: "Upload your file",
    description: "Drop the executable file (max 32MB). SafeCheck computes SHA-256 and checks VirusTotal cache first.",
  },
  {
    step: 2,
    icon: FileArchive,
    title: "Analyze torrent metadata",
    description: "Optionally inspect .torrent or magnet metadata when validating legal software or media distributions.",
  },
  {
    step: 3,
    icon: CheckCircle,
    title: "Get your verdict",
    description: "Receive a clear Safe, Suspicious, or Dangerous verdict with a plain-English explanation and recommended action.",
  },
];

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
            Three simple steps to peace of mind. No account needed, no software to install.
          </p>
        </motion.div>

        <div className="max-w-4xl mx-auto">
          {steps.map((item, index) => (
            <motion.div
              key={item.step}
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.2, duration: 0.5 }}
              className="relative"
            >
              <div className="flex gap-6 md:gap-10 items-start mb-12">
                {/* Step number with connecting line */}
                <div className="relative flex flex-col items-center">
                  <div className="w-16 h-16 rounded-2xl bg-primary/10 border border-primary/30 flex items-center justify-center">
                    <item.icon className="w-7 h-7 text-primary" />
                  </div>
                  {index < steps.length - 1 && (
                    <div className="absolute top-20 w-px h-16 bg-gradient-to-b from-primary/50 to-transparent" />
                  )}
                </div>

                {/* Content */}
                <div className="flex-1 pt-2">
                  <div className="flex items-center gap-3 mb-2">
                    <span className="text-sm font-semibold text-primary">Step {item.step}</span>
                  </div>
                  <h3 className="font-display text-2xl font-semibold mb-3">{item.title}</h3>
                  <p className="text-muted-foreground leading-relaxed max-w-lg">{item.description}</p>
                </div>
              </div>
            </motion.div>
          ))}
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
            <span>Results in under 30 seconds</span>
            <ArrowDown className="w-4 h-4 animate-bounce" />
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default HowItWorks;
