FROM node:22-alpine AS build
WORKDIR /app
# Copy the lockfile too and use `npm ci` so image builds are reproducible and
# match the dependency tree audited in CI.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.30-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
