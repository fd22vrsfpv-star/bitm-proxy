sudo apt update && sudo apt install -y git curl ca-certificates build-essential \
      python3 python3-venv python3-pip openssl && \                                                                     
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && \
  sudo apt install -y nodejs && \                                                                                       
  curl -fsSL https://go.dev/dl/go1.22.10.linux-amd64.tar.gz | sudo tar -C /usr/local -xz && \
  export PATH=/usr/local/go/bin:$PATH && \ 
