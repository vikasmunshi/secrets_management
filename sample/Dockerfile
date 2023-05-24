FROM python:3.12-rc-slim
RUN python3 -m pip install cryptography
RUN python3 -m pip install -e git+https://github.com/vikasmunshi/secrets_management.git#egg=cloak-0.4.427290
ADD https://raw.githubusercontent.com/vikasmunshi/secrets_management/master/sample/sample.json /etc/sample.json
# command to generate rsa private key and certificate signing request, use RUN only for testing
# RUN python3 -m cloak csr /etc/sample.json
# CMD ["python3" ,"-m", "cloak", "csr", "/etc/sample.json" ]
# CMD ["python3", "-i", "-c", "import cloak, cloak.tests"]
# build and start interactive shell to
# docker build -t cloak .
# docker run --name cloak cloak /bin/bash
