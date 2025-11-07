FROM golang:1.18-bullseye

RUN apt-get updated && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

CMD ["zsh"]
