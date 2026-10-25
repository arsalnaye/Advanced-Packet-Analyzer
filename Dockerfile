# Build the React/Vite frontend.
FROM node:22-bookworm-slim AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package.json ./package.json
RUN npm install
COPY frontend/ ./
RUN npm run build

# Compile the existing C++17 DPI engine on Linux.
FROM python:3.12-slim-bookworm AS engine-builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY include/ ./include/
COPY src/ ./src/
RUN mkdir -p /build/backend/bin \
    && g++ -std=c++17 -pthread -O2 -I /build/include \
       -o /build/backend/bin/dpi_engine \
       /build/src/dpi_mt.cpp \
       /build/src/pcap_reader.cpp \
       /build/src/packet_parser.cpp \
       /build/src/sni_extractor.cpp \
       /build/src/types.cpp

# Runtime image: FastAPI serves both /api endpoints and the built frontend.
FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN python -m pip install --no-cache-dir -r backend/requirements.txt
COPY include/ ./include/
COPY src/ ./src/
COPY backend/ ./backend/
COPY --from=engine-builder /build/backend/bin/dpi_engine ./backend/bin/dpi_engine
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist
EXPOSE 10000
CMD ["sh", "-c", "uvicorn backend.app:app --host 0.0.0.0 --port ${PORT:-10000}"]
