ARG ARCH=
FROM gcr.io/distroless/python3-debian11:nonroot${ARCH}
COPY galery /app
COPY get-pip.py /get-pip.py
RUN python /get-pip.py
RUN python -m pip install --disable-pip-version-check --upgrade -r /app/requirements.txt
WORKDIR /app
CMD ["app.py"]
