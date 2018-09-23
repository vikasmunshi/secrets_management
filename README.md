# secrets management
## install
### source
    git clone https://github.com/vikasmunshi/secrets_management.git
    python3 -m pip install -e secrets_management
### pip
    python3 -m pip install -e git+https://github.com/vikasmunshi/secrets_management.git#egg=cloak-0.3.427145
### docker
    curl https://raw.githubusercontent.com/vikasmunshi/secrets_management/master/Dockerfile -o Dockerfile
    docker build -t cloak . && docker run --name cloak cloak 
    