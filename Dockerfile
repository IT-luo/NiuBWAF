# ---------- 构建阶段 ----------
FROM golang:1.26.11-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/niubwaf .

# ---------- 运行阶段 ----------
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 niubwaf \
    && adduser -S -D -H -u 10001 -G niubwaf niubwaf
WORKDIR /app
COPY --from=builder /out/niubwaf /app/niubwaf
COPY data/geoip.mmdb /app/seed/geoip.mmdb
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN mkdir -p /app/data \
    && chown niubwaf:niubwaf /app/data \
    && chmod +x /app/niubwaf /app/docker-entrypoint.sh

ENV TZ=Asia/Shanghai
VOLUME /app/data
EXPOSE 8080 8443 9443

USER niubwaf
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["-proxy", ":8080", "-tls", ":8443", "-admin", ":9443", "-data", "/app/data"]
