FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg python3 make g++ ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY . .
ENV HOST=0.0.0.0 CLOUD_MODE=true NODE_ENV=production
CMD ["sh", "scripts/cloud-start.sh"]
