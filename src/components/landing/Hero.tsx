import Link from 'next/link';

export default function Hero() {
  return (
    <section className="min-h-screen flex items-center justify-center relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-black to-gray-900"></div>
      <div className="absolute inset-0 opacity-10">
        <div className="absolute top-1/4 left-1/4 w-64 h-64 border border-gray-800 rounded-full animate-pulse"></div>
        <div className="absolute bottom-1/3 right-1/3 w-48 h-48 border border-gray-800 rounded-full animate-pulse delay-1000"></div>
      </div>
      
      <div className="relative z-10 text-center max-w-4xl px-4">
        <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold mb-6 leading-tight">
          AI-Driven Trading Intelligence for Informed Decision-Making
        </h1>
        <p className="text-xl md:text-2xl text-gray-300 mb-12 max-w-3xl mx-auto leading-relaxed">
          Advanced multi-model AI architecture providing context-aware market analysis and risk evaluation
        </p>
        
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link 
            href="/login" 
            className="px-8 py-4 bg-blue-600 text-white text-lg rounded-lg hover:bg-blue-700 transition transform hover:scale-105"
          >
            Request Access
          </Link>
          <Link 
            href="#capabilities" 
            className="px-8 py-4 bg-transparent border border-gray-700 text-white text-lg rounded-lg hover:bg-gray-800 transition"
          >
            Learn More
          </Link>
        </div>
      </div>
    </section>
  );
}