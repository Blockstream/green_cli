FROM python@sha256:c1613835d7be322f98603f356b9e0c9d40f9589e94dc9f710e714a807a665700
COPY . /green-cli
WORKDIR /green-cli
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN pip install -e .
ENTRYPOINT ["green-cli", "-C", "/config"]
