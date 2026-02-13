import { motion } from "framer-motion";
import { Shield, FileSearch, Hash, AlertTriangle, FileArchive } from "lucide-react";

const features = [
  {
    icon: FileArchive,
    title: "Torrent Metadata Analysis",
    description: "Preview file contents in Linux ISOs, open software distributions, and public domain media torrents.",
    color: "text-primary",
    bgColor: "bg-primary/10",
  },
  {
    icon: FileSearch,
    title: "Smart Scan Analysis",
    description: "Verify software downloaded from mirror links or unofficial sources with VirusTotal engine results.",
    color: "text-accent",
    bgColor: "bg-accent/10",
  },
  {
    icon: Hash,
    title: "Hash Verification",
    description: "Confirm cloud backups and downloaded installers were not corrupted or tampered with in transfer.",
    color: "text-safe",
    bgColor: "bg-safe/10",
  },
  {
    icon: AlertTriangle,
    title: "Clear Verdicts",
    description: "Interpret complex antivirus outputs for non-technical users with a weighted Safe/Suspicious/Dangerous verdict.",
    color: "text-suspicious",
    bgColor: "bg-suspicious/10",
  },
];

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
          {features.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1, duration: 0.5 }}
            >
              <div className="glass-card p-8 h-full hover:border-primary/50 transition-all duration-300 group">
                <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${feature.bgColor} mb-6 group-hover:scale-110 transition-transform duration-300`}>
                  <feature.icon className={`w-7 h-7 ${feature.color}`} />
                </div>
                <h3 className="font-display text-xl font-semibold mb-3">{feature.title}</h3>
                <p className="text-muted-foreground leading-relaxed">{feature.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Features;
