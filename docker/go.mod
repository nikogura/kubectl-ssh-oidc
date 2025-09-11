// This file prevents Go from treating docker/ as part of the main module
// The docker/dex/ssh.go file is only used during Docker builds
module docker

go 1.21