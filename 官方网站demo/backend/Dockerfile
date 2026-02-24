FROM golang:1.21-alpine AS build
WORKDIR /app
RUN apk add --no-cache git
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o server .

FROM alpine:3.19
WORKDIR /app
RUN mkdir -p /data /uploads
COPY --from=build /app/server /app/server
# default seed config (required on first boot)
COPY --from=build /app/default_site_config.json /app/default_site_config.json
EXPOSE 8080
CMD ["./server"]
