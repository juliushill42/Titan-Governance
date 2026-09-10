FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /gateway ./cmd/gateway

FROM alpine:3.20
RUN adduser -D -u 10001 gateway
COPY --from=build /gateway /gateway
USER gateway
EXPOSE 8090
ENTRYPOINT ["/gateway"]
