import { NewsContainer } from './NewsContainer';
import { NewsHeader } from './NewsHeader';

export default async function NewsPage() {
  return (
    <div className="min-h-screen bg-black text-white">
      <NewsHeader />
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        <NewsContainer />
      </main>
    </div>
  );
}
