export default function CoreCapabilities() {
  const capabilities = [
    {
      title: "AI-Driven Market State Awareness",
      description: "QuantumIQ continuously analyzes market conditions across multiple dimensions, providing real-time context for decision-making. The system identifies regime changes, volatility patterns, and structural shifts without relying on single-factor analysis.",
      color: "blue-400"
    },
    {
      title: "Multi-Factor Decision Intelligence",
      description: "Rather than simplistic signals, QuantumIQ synthesizes multiple analytical perspectives to generate nuanced, context-aware insights. Each decision recommendation is backed by multi-model consensus and transparent reasoning.",
      color: "blue-400"
    },
    {
      title: "Dynamic Risk Evaluation",
      description: "Risk assessment adapts to changing market conditions in real-time. QuantumIQ evaluates position-level, portfolio-level, and systemic risk factors to support responsible trading decisions.",
      color: "blue-400"
    },
    {
      title: "Explainable AI Decision Logic",
      description: "Every recommendation includes a clear explanation of contributing factors, model reasoning, and confidence levels. No black-box outputs—full transparency into why the system suggests what it does.",
      color: "blue-400"
    }
  ];

  return (
    <section id="capabilities" className="py-20 px-4 bg-gray-900">
      <div className="max-w-6xl mx-auto">
        <h2 className="text-3xl md:text-4xl font-bold text-center mb-16">Core Capabilities</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          {capabilities.map((capability, index) => (
            <div key={index} className="bg-gray-800 p-8 rounded-xl border border-gray-700">
              <h3 className="text-2xl font-semibold mb-4 text-blue-400">{capability.title}</h3>
              <p className="text-gray-300">{capability.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}