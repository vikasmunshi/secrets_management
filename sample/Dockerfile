FROM python:3.7
RUN python3 -m pip install cryptography
RUN python3 -m pip install -e git+https://github.com/vikasmunshi/secrets_management.git#egg=cloak-0.4.427280
ADD https://raw.githubusercontent.com/vikasmunshi/secrets_management/master/sample/sample.json /etc/cert.json
ADD https://raw.githubusercontent.com/vikasmunshi/secrets_management/master/policy/ca.pem /etc/ca.pem
# command to generate rsa private key and certificate signing request, use RUN only for testing
#RUN python3 -m cloak csr /etc/cert.json
#CMD ["python3", "-i" ,"-m", "cloak", "csr", "https://raw.githubusercontent.com/vikasmunshi/secrets_management/master/sample/sample.json" ]
# command to start interactive python shell in console
#CMD ["python3", "-i", "-c", "import cloak, cloak.tests, os"]
