FROM golang:1.22

WORKDIR /var/www/go

COPY . /var/www/go

RUN go mod download

RUN go install -mod=mod github.com/githubnemo/CompileDaemon

ENTRYPOINT CompileDaemon --build="go build -o auth-server ./service-auth/cmd/server/main.go" --command=./auth-server
