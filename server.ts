/**
 * Custom Next.js Server with Security Initialization
 * Ensures security components are initialized before serving requests
 */

import { createServer } from 'http';
import { parse } from 'url';
import next from 'next';
import { AppStartup } from './src/lib/app-startup';

// Initialize security before starting the server
async function startServer() {
  try {
    // Initialize application security
    await AppStartup.initialize();
    
    console.log('Security initialization completed, starting Next.js server...');
    
    const dev = process.env.NODE_ENV !== 'production';
    const hostname = process.env.HOST || 'localhost';
    const port = parseInt(process.env.PORT || '3000', 10);
    
    const app = next({ dev, hostname, port });
    const handle = app.getRequestHandler();
    
    await app.prepare();
    
    const server = createServer(async (req, res) => {
      try {
        // Be sure to pass `true` as the second argument to `parse` 
        // so the query string is properly parsed
        const parsedUrl = parse(req.url!, true);
        await handle(req, res, parsedUrl);
      } catch (err) {
        console.error('Error occurred handling request:', err);
        res.statusCode = 500;
        res.end('Internal Server Error');
      }
    });
    
    server.listen(port, hostname, () => {
      console.log(`Server is running on http://${hostname}:${port}`);
    });
  } catch (error) {
    console.error('Failed to start server due to security initialization error:', error);
    process.exit(1);
  }
}

// Start the server
startServer().catch(error => {
  console.error('Fatal error starting server:', error);
  process.exit(1);
});