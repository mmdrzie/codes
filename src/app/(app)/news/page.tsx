export default function NewsPage() {
  return (
    <div className="max-w-7xl mx-auto">
      <h1 className="text-4xl font-bold mb-8">News</h1>
      <p className="text-lg text-gray-600">Welcome to the News section of QuantumIQ.</p>
      <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-8">
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-2xl font-semibold mb-4">Feature 1</h2>
          <p>Content placeholder</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-2xl font-semibold mb-4">Feature 2</h2>
          <p>Content placeholder</p>
        </div>
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-2xl font-semibold mb-4">Feature 3</h2>
          <p>Content placeholder</p>
        </div>
      </div>
    </div>
  );
}
