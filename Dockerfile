# Multi-stage build for the PKI test services.
# Stage 1 builds the static Go binaries; stage 2 is a minimal runtime image.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /out/pkitool   ./cmd/pkitool  && \
    CGO_ENABLED=0 go build -o /out/pkiserver ./cmd/pkiserver && \
    CGO_ENABLED=0 go build -o /out/certify   ./cmd/certify

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/pkitool   /app/pkitool
COPY --from=build /out/pkiserver /app/pkiserver
COPY --from=build /out/certify   /app/certify
COPY config /app/config
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/pkiserver"]
