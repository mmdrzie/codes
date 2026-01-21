#!/bin/bash

# Install liboqs from source
echo "Installing liboqs..."

# Install build dependencies
apt-get update
apt-get install -y git cmake gcc ninja-build

# Clone and build liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
ninja
ninja install

# Update library cache
ldconfig

cd ../..

# Now install the Node.js bindings
npm install --save --legacy-peer-deps @oqs/node

echo "Installation complete!"