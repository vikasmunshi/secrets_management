FROM python:3.7
RUN python3 -m pip install -e git+https://github.com/vikasmunshi/secrets_management.git#egg=cloak-0.3.25627594
CMD ["python3", "-i", "-c", "import cloak"]