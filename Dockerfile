FROM python:3.13-slim-trixie@sha256:27f90d79cc85e9b7b2560063ef44fa0e9eaae7a7c3f5a9f74563065c5477cc24
COPY . /green-cli
WORKDIR /green-cli
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install -e .
ENTRYPOINT ["green-cli", "-C", "/config"]
