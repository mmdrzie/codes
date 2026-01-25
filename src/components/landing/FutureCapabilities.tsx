export default function FutureCapabilities() {
  const features = [
    "Multi-model trading strategies (different AI models with distinct behavioral profiles)",
    "AI-assisted automated execution (subject to rigorous testing and regulatory compliance)",
    "Conversational AI interface for multi-model interaction",
    "Macro-economic and news-aware decision adjustments",
    "Advanced scenario analysis and what-if reasoning"
  ];

  return (
    <section className="py-20 px-4">
      <div className="max-w-4xl mx-auto">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-12">In Development</h2>
        
        <ul className="space-y-4 max-w-2xl mx-auto">
          {features.map((feature, index) => (
            <li key={index} className="flex items-start">
              <span className="text-green-500 mr-3 mt-1">✓</span>
              <span className="text-lg">{feature}</span>
            </li>
          ))}
        </ul>
        
        <p className="text-gray-500 text-center mt-8 italic">
          Future capabilities are under development and subject to change. No guarantees of availability, performance, or outcomes.
        </p>
      </div>
    </section>
  );
}