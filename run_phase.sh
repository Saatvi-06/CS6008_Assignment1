#!/bin/bash
echo "======================================"
echo "    Compiling All Secure Chat Phases  "
echo "======================================"

echo "[1/5] Building Phase 1..."
cd phase1
g++ -o server server.cpp
g++ -o client client.cpp -pthread
cd ..

echo "[2/5] Building Phase 2..."
cd phase2
g++ -o server server.cpp -lssl -lcrypto
g++ -o client client.cpp -pthread -lssl -lcrypto
g++ -o mitm mitm.cpp -lssl -lcrypto
cd ..

echo "[3/5] Building Phase 3..."
cd phase3
g++ -o server server.cpp -lssl -lcrypto
g++ -o client client.cpp -pthread -lssl -lcrypto
g++ -o mitm mitm.cpp -lssl -lcrypto
cd ..

echo "[4/5] Building Phase 4..."
cd phase4
g++ -o server server.cpp -lssl -lcrypto
g++ -o client client.cpp -pthread -lssl -lcrypto
g++ -o mitm mitm.cpp -lssl -lcrypto
cd ..

echo "[5/5] Building Phase 5..."
cd phase5
g++ -o server server.cpp -lssl -lcrypto
g++ -o client client.cpp -pthread -lssl -lcrypto
g++ -o mitm mitm.cpp -lssl -lcrypto
cd ..

echo ""
echo "======================================"
echo "  All phases compiled successfully!   "
echo "======================================"
