export default function MultiModelArchitecture() {
  return (
    <section className="py-20 px-4">
      <div className="max-w-4xl mx-auto text-center">
        <h2 className="text-3xl md:text-4xl font-bold mb-8">Multi-Model Architecture</h2>
        <p className="text-xl text-gray-300 mb-12">
          QuantumIQ employs multiple specialized AI models, each optimized for different market conditions and decision contexts. This ensemble approach reduces single-model bias and improves decision robustness. Models operate independently and in consensus, with human-in-the-loop oversight.
        </p>
        
        <div className="bg-gray-900 p-8 rounded-xl border border-gray-700 max-w-2xl mx-auto">
          <div className="flex flex-wrap justify-center gap-6">
            <div className="text-center">
              <div className="w-16 h-16 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-2">
                <span className="text-xl">A</span>
              </div>
              <p className="text-sm text-gray-400">Model A</p>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-2">
                <span className="text-xl">B</span>
              </div>
              <p className="text-sm text-gray-400">Model B</p>
            </div>
            <div className="text-center">
              <div className="w-16 h-16 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-2">
                <span className="text-xl">C</span>
              </div>
              <p className="text-sm text-gray-400">Model C</p>
            </div>
          </div>
          <div className="mt-6 text-center">
            <div className="inline-block px-4 py-2 bg-gray-700 rounded-lg text-sm">Consensus Engine</div>
          </div>
        </div>
      </div>
    </section>
  );
}