FROM python:3
RUN pip install -e git+https://github.com/vikasmunshi/secrets_management.git#egg=cloak-0.2.2
CMD ["python", "-m", "cloak.tests"]