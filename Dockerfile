FROM python:3.7
RUN python3 -m pip install cryptography
RUN python3 -m pip install -e git+https://github.com/vikasmunshi/secrets_management.git#egg=cloak-0.3.427200
# command to generate rsa private key and certificate signing request
CMD ["python3", "-m", "cloak", "csr", "template.json" ]
# command to start interactive python shell in console
#CMD ["python3", "-i", "-c", "import cloak, cloak.tests"]
