FROM golang:1.20.12-alpine as builder
ARG GITHUB_TOKEN
RUN apk update && apk add --no-cache gcc musl-dev git
RUN git config --global url."https://$GITHUB_TOKEN:x-oauth-basic@github.com/".insteadOf "https://github.com/"
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN go build -ldflags '-w -s' -a -o telifi ./crypto/tss/ecdsa/wasm/server/main.go

# Deployment environment
# ----------------------
FROM alpine:3.19
WORKDIR /app
RUN chown nobody:nobody /app
USER nobody:nobody
COPY --from=builder --chown=nobody:nobody ./app/telifi .
COPY --from=builder --chown=nobody:nobody ./app/run.sh .

ENTRYPOINT sh run.sh
