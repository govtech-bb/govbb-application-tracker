FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production \
    PORT=3030 \
    TRACKER_DATA_DIR=/var/data \
    MAIL_OUT_DIR=/var/data/mail-out

RUN mkdir -p /var/data && chown -R node:node /var/data

USER node
EXPOSE 3030

CMD sh -c "node seed.js && node server.js"
