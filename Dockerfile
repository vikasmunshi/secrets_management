FROM python:3.7
RUN python3 -m pip install -e git+https://github.com/vikasmunshi/secrets_management.git#egg=cloak-0.3.427156
CMD ["python3", "-i", "-m", "cloak", "csr", "template.json" ]
#CMD ["python3", "-i", "-c", "import cloak, cloak.tests"]
