import Link from 'next/link';

export default function Footer() {
  return (
    <footer className="py-12 px-4 border-t border-gray-800">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-8">
          <p className="text-gray-400 mb-4">
            QuantumIQ is a decision-support platform. Trading involves risk of loss. Past performance does not guarantee future results. Users are responsible for their own trading decisions.
          </p>
          <div className="flex justify-center space-x-6 mb-4">
            <Link href="/privacy" className="text-gray-500 hover:text-white transition">Privacy Policy</Link>
            <Link href="/terms" className="text-gray-500 hover:text-white transition">Terms of Service</Link>
          </div>
          <p className="text-gray-600">© 2025 QuantumIQ. All rights reserved.</p>
        </div>
        
        <div className="text-center">
          <Link 
            href="/login" 
            className="inline-block px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition"
          >
            Request Access
          </Link>
        </div>
      </div>
    </footer>
  );
}