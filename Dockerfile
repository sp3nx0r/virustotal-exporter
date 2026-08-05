# syntax=docker/dockerfile:1

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/virustotal-exporter ./cmd/virustotal-exporter

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/virustotal-exporter /virustotal-exporter
EXPOSE 9942
USER nonroot:nonroot
ENTRYPOINT ["/virustotal-exporter"]
