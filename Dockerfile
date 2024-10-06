FROM golang:1.22-alpine AS builder

WORKDIR /go/src/backend

RUN apk --update --no-cache add ca-certificates gcc libtool make musl-dev protoc git

COPY . /go/src/backend
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o backend cmd/backend/*.go

FROM scratch

COPY --from=builder /go/src/backend/backend backend
COPY --from=builder /go/src/backend/config/config.yaml /config/config.yaml
COPY --from=builder /go/src/backend/.env ./
COPY --from=builder /go/src/backend/internal/migrations/* /migrations/

EXPOSE 8080

ENTRYPOINT ["/backend"]
