# syntax=docker/dockerfile:1
# Build: docker build -t checklein .
# Run:   docker run --rm -p 127.0.0.1:8787:8787 checklein

FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p checklein-cli

# glibc must match the build stage: bookworm (Debian 12) on both sides.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/checklein /usr/local/bin/checklein
EXPOSE 8787
USER nonroot
ENTRYPOINT ["checklein"]
# Inside a container network, listen on all interfaces; publish the port only
# to your proxy, never to the internet (forwarding headers are trusted).
CMD ["serve", "--listen", "0.0.0.0:8787"]
