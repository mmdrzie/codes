# Use official Node.js runtime as base image
FROM node:18-alpine AS base

# Install dumb-init to properly handle signals
RUN apk add --no-cache dumb-init

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Copy source code
COPY . .

# Change ownership to non-root user
RUN chown -R nextjs:nodejs /app
USER nextjs

# Build the application
RUN npm run build

# Expose port
EXPOSE 3000

# Use dumb-init to handle graceful shutdowns
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["npm", "start"]